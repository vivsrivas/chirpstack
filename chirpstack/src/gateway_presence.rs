use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration as StdDuration;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use redis::Script;
use serde::Serialize;
use tokio::time::sleep;
use tracing::{error, info, trace, warn};

use crate::config;
use crate::helpers::errors::PrintFullError;
use crate::monitoring::prometheus;
use crate::storage::{get_async_redis_conn, redis_key};
use crate::stream;
use lrwn::EUI64;

const HEARTBEAT_SCRIPT: &str = r#"
local prev = redis.call("GET", KEYS[3]) or ""
redis.call("SET", KEYS[1], ARGV[1], "EX", ARGV[2])
redis.call("ZADD", KEYS[2], ARGV[3], ARGV[4])
redis.call("SET", KEYS[3], "online", "EX", ARGV[5])
return prev
"#;

const CLAIM_DUE_SCRIPT: &str = r#"
local ids = redis.call("ZRANGEBYSCORE", KEYS[1], "-inf", ARGV[1], "LIMIT", 0, ARGV[2])
if #ids > 0 then
  redis.call("ZREM", KEYS[1], unpack(ids))
end
return ids
"#;

const OFFLINE_TRANSITION_SCRIPT: &str = r#"
if redis.call("EXISTS", KEYS[1]) == 1 then
  return 0
end
local prev = redis.call("GET", KEYS[2])
if prev == "offline" then
  redis.call("EXPIRE", KEYS[2], ARGV[1])
  return 0
end
redis.call("SET", KEYS[2], "offline", "EX", ARGV[1])
return 1
"#;

#[derive(Serialize)]
struct GatewayPresenceEvent {
    gateway_id: String,
    state: String,
    time_seconds: i64,
    time_nanos: u32,
}

static GATEWAY_PRESENCE_HEARTBEAT_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let counter = Counter::default();
    prometheus::register(
        "gateway_presence_heartbeat_total",
        "Total number of gateway presence heartbeats processed",
        counter.clone(),
    );
    counter
});
static GATEWAY_PRESENCE_HEARTBEAT_ERROR_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let counter = Counter::default();
    prometheus::register(
        "gateway_presence_heartbeat_error_total",
        "Total number of gateway presence heartbeat errors",
        counter.clone(),
    );
    counter
});
static GATEWAY_PRESENCE_ONLINE_TRANSITIONS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let counter = Counter::default();
    prometheus::register(
        "gateway_presence_online_transitions_total",
        "Total number of gateway online transitions emitted",
        counter.clone(),
    );
    counter
});
static GATEWAY_PRESENCE_OFFLINE_TRANSITIONS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let counter = Counter::default();
    prometheus::register(
        "gateway_presence_offline_transitions_total",
        "Total number of gateway offline transitions emitted",
        counter.clone(),
    );
    counter
});
static GATEWAY_PRESENCE_DUE_CLAIMED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let counter = Counter::default();
    prometheus::register(
        "gateway_presence_due_claimed_total",
        "Total number of due gateway presence entries claimed by detector",
        counter.clone(),
    );
    counter
});
static GATEWAY_PRESENCE_SHARD_ERROR_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let counter = Counter::default();
    prometheus::register(
        "gateway_presence_shard_error_total",
        "Total number of gateway presence shard processing errors",
        counter.clone(),
    );
    counter
});
static GATEWAY_PRESENCE_LOOP_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    let histogram = Histogram::new(exponential_buckets(0.001, 2.0, 12));
    prometheus::register(
        "gateway_presence_detector_loop_duration_seconds",
        "Duration of one full gateway presence detector loop over all shards",
        histogram.clone(),
    );
    histogram
});

pub async fn setup() {
    let conf = config::get();
    if !conf.network.gateway_presence.enabled {
        info!("Gateway presence tracking disabled");
        return;
    }

    info!("Setting up gateway presence offline detector loop");
    tokio::spawn(async move {
        offline_detector_loop().await;
    });
}

pub async fn heartbeat(gateway_id: EUI64, offline_threshold: StdDuration) -> Result<()> {
    let conf = config::get();
    let p = &conf.network.gateway_presence;
    if !p.enabled {
        return Ok(());
    }

    let effective_offline_threshold = if offline_threshold.is_zero() {
        p.offline_threshold
    } else {
        offline_threshold
    };

    let now = Utc::now();
    let now_ms = now.timestamp_millis();
    let last_ttl_secs = (effective_offline_threshold + p.grace_period)
        .as_secs()
        .max(1) as usize;
    let state_ttl_secs = p.state_ttl.as_secs().max(1) as usize;
    let expires_at_ms = now_ms + (effective_offline_threshold + p.grace_period).as_millis() as i64;
    let gateway_id_s = gateway_id.to_string();
    let shard = shard_for_gateway_id(gateway_id, p.shards);

    let mut conn = get_async_redis_conn().await?;
    let prev_state: String = match Script::new(HEARTBEAT_SCRIPT)
        .key(last_seen_key(shard, &gateway_id_s))
        .key(expiry_key(shard))
        .key(state_key(shard, &gateway_id_s))
        .arg(now_ms)
        .arg(last_ttl_secs)
        .arg(expires_at_ms)
        .arg(&gateway_id_s)
        .arg(state_ttl_secs)
        .invoke_async(&mut conn)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            GATEWAY_PRESENCE_HEARTBEAT_ERROR_TOTAL.inc();
            return Err(e.into());
        }
    };
    GATEWAY_PRESENCE_HEARTBEAT_TOTAL.inc();

    if prev_state.is_empty() || prev_state == "offline" {
        emit_presence_event(&gateway_id_s, "online").await?;
        GATEWAY_PRESENCE_ONLINE_TRANSITIONS_TOTAL.inc();
    }

    Ok(())
}

pub async fn get_last_seen(gateway_id: EUI64) -> Result<Option<chrono::DateTime<Utc>>> {
    let conf = config::get();
    let p = &conf.network.gateway_presence;
    if !p.enabled {
        return Ok(None);
    }

    let gateway_id_s = gateway_id.to_string();
    let shard = shard_for_gateway_id(gateway_id, p.shards);
    let key = last_seen_key(shard, &gateway_id_s);

    let mut conn = get_async_redis_conn().await?;
    let value: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;

    Ok(value.and_then(|v| parse_last_seen_ts(&v)))
}

pub async fn get_last_seen_many(
    gateway_ids: &[EUI64],
) -> Result<HashMap<String, chrono::DateTime<Utc>>> {
    let mut out: HashMap<String, chrono::DateTime<Utc>> = HashMap::new();
    if gateway_ids.is_empty() {
        return Ok(out);
    }

    let conf = config::get();
    let p = &conf.network.gateway_presence;
    if !p.enabled {
        return Ok(out);
    }

    let mut by_shard: HashMap<u32, Vec<String>> = HashMap::new();
    for gateway_id in gateway_ids {
        let gateway_id_s = gateway_id.to_string();
        let shard = shard_for_gateway_id(*gateway_id, p.shards);
        by_shard.entry(shard).or_default().push(gateway_id_s);
    }

    let mut conn = get_async_redis_conn().await?;
    for (shard, gateway_ids) in by_shard {
        let keys: Vec<String> = gateway_ids
            .iter()
            .map(|gateway_id| last_seen_key(shard, gateway_id))
            .collect();

        let values: Vec<Option<String>> =
            redis::cmd("MGET").arg(keys).query_async(&mut conn).await?;
        for (gateway_id, value) in gateway_ids.iter().zip(values.into_iter()) {
            if let Some(v) = value.and_then(|ts| parse_last_seen_ts(&ts)) {
                out.insert(gateway_id.clone(), v);
            }
        }
    }

    Ok(out)
}

pub async fn get_state_many(gateway_ids: &[EUI64]) -> Result<HashMap<String, String>> {
    let mut out: HashMap<String, String> = HashMap::new();
    if gateway_ids.is_empty() {
        return Ok(out);
    }

    let conf = config::get();
    let p = &conf.network.gateway_presence;
    if !p.enabled {
        return Ok(out);
    }

    let mut by_shard: HashMap<u32, Vec<String>> = HashMap::new();
    for gateway_id in gateway_ids {
        let gateway_id_s = gateway_id.to_string();
        let shard = shard_for_gateway_id(*gateway_id, p.shards);
        by_shard.entry(shard).or_default().push(gateway_id_s);
    }

    let mut conn = get_async_redis_conn().await?;
    for (shard, gateway_ids) in by_shard {
        let keys: Vec<String> = gateway_ids
            .iter()
            .map(|gateway_id| state_key(shard, gateway_id))
            .collect();

        let values: Vec<Option<String>> =
            redis::cmd("MGET").arg(keys).query_async(&mut conn).await?;
        for (gateway_id, value) in gateway_ids.iter().zip(values.into_iter()) {
            if let Some(v) = value {
                out.insert(gateway_id.clone(), v);
            }
        }
    }

    Ok(out)
}

pub async fn should_update_db_state(gateway_id: EUI64, interval: StdDuration) -> Result<bool> {
    if interval.is_zero() {
        return Ok(true);
    }

    let conf = config::get();
    let p = &conf.network.gateway_presence;
    let shard = shard_for_gateway_id(gateway_id, p.shards);
    let key = db_update_key(shard, &gateway_id.to_string());
    let ttl_secs = interval.as_secs().max(1) as usize;

    let mut conn = get_async_redis_conn().await?;
    let resp: Option<String> = redis::cmd("SET")
        .arg(key)
        .arg("1")
        .arg("EX")
        .arg(ttl_secs)
        .arg("NX")
        .query_async(&mut conn)
        .await?;

    Ok(resp.is_some())
}

async fn offline_detector_loop() {
    loop {
        let loop_start = Instant::now();
        let conf = config::get();
        let p = &conf.network.gateway_presence;

        if !p.enabled {
            sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        for shard in 0..p.shards.max(1) {
            if let Err(e) = process_shard(shard).await {
                GATEWAY_PRESENCE_SHARD_ERROR_TOTAL.inc();
                error!(shard, error = %e.full(), "Gateway presence shard processing error");
            }
        }
        GATEWAY_PRESENCE_LOOP_DURATION.observe(loop_start.elapsed().as_secs_f64());

        sleep(p.check_interval).await;
    }
}

async fn process_shard(shard: u32) -> Result<()> {
    let conf = config::get();
    let p = &conf.network.gateway_presence;
    let now_ms = Utc::now().timestamp_millis();

    let mut conn = get_async_redis_conn().await?;
    let due_gateway_ids: Vec<String> = Script::new(CLAIM_DUE_SCRIPT)
        .key(expiry_key(shard))
        .arg(now_ms)
        .arg(p.batch_size.max(1))
        .invoke_async(&mut conn)
        .await?;

    if due_gateway_ids.is_empty() {
        return Ok(());
    }

    trace!(
        shard,
        count = due_gateway_ids.len(),
        "Claimed due gateway presence entries"
    );
    GATEWAY_PRESENCE_DUE_CLAIMED_TOTAL.inc_by(due_gateway_ids.len() as u64);

    let state_ttl_secs = p.state_ttl.as_secs().max(1) as usize;
    for gateway_id in due_gateway_ids {
        let became_offline: i32 = Script::new(OFFLINE_TRANSITION_SCRIPT)
            .key(last_seen_key(shard, &gateway_id))
            .key(state_key(shard, &gateway_id))
            .arg(state_ttl_secs)
            .invoke_async(&mut conn)
            .await?;

        if became_offline == 1
            && let Err(e) = emit_presence_event(&gateway_id, "offline").await
        {
            warn!(gateway_id = %gateway_id, error = %e.full(), "Emit offline event error");
        } else if became_offline == 1 {
            GATEWAY_PRESENCE_OFFLINE_TRANSITIONS_TOTAL.inc();
        }
    }

    Ok(())
}

async fn emit_presence_event(gateway_id: &str, state: &str) -> Result<()> {
    let now = Utc::now();
    let pl = GatewayPresenceEvent {
        gateway_id: gateway_id.to_string(),
        state: state.to_string(),
        time_seconds: now.timestamp(),
        time_nanos: now.timestamp_subsec_nanos(),
    };
    let b = serde_json::to_vec(&pl)?;
    stream::event::log_event_for_gateway(state, gateway_id, &b).await?;
    Ok(())
}

fn shard_for_gateway_id(gateway_id: EUI64, shards: u32) -> u32 {
    if shards <= 1 {
        return 0;
    }

    let v = u64::from_be_bytes(gateway_id.to_be_bytes());
    (v % shards as u64) as u32
}

fn hash_tag(shard: u32) -> String {
    format!("presence:{}", shard)
}

fn expiry_key(shard: u32) -> String {
    let tag = hash_tag(shard);
    redis_key(format!("gw:expiry:{{{}}}", tag))
}

fn last_seen_key(shard: u32, gateway_id: &str) -> String {
    let tag = hash_tag(shard);
    redis_key(format!("gw:last:{{{}}}:{}", tag, gateway_id))
}

fn state_key(shard: u32, gateway_id: &str) -> String {
    let tag = hash_tag(shard);
    redis_key(format!("gw:state:{{{}}}:{}", tag, gateway_id))
}

fn db_update_key(shard: u32, gateway_id: &str) -> String {
    let tag = hash_tag(shard);
    redis_key(format!("gw:lastdb:{{{}}}:{}", tag, gateway_id))
}

fn parse_last_seen_ts(v: &str) -> Option<chrono::DateTime<Utc>> {
    let ts_ms: i64 = v.parse().ok()?;
    chrono::DateTime::<Utc>::from_timestamp_millis(ts_ms)
}

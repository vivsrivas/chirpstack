use anyhow::Result;
use chrono::Utc;
use redis::Script;
use serde::Serialize;
use std::collections::HashMap;
use tokio::time::sleep;
use tracing::{error, info, trace, warn};

use crate::config;
use crate::helpers::errors::PrintFullError;
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
struct PresenceEvent {
    dev_eui: String,
    state: String,
    time_seconds: i64,
    time_nanos: u32,
}

pub async fn setup() {
    let conf = config::get();
    if !conf.network.device_presence.enabled {
        info!("Device presence tracking disabled");
        return;
    }

    info!("Setting up device presence offline detector loop");
    tokio::spawn(async move {
        offline_detector_loop().await;
    });
}

pub async fn heartbeat(dev_eui: EUI64) -> Result<()> {
    let conf = config::get();
    let p = &conf.network.device_presence;
    if !p.enabled {
        return Ok(());
    }

    let now = Utc::now();
    let now_ms = now.timestamp_millis();
    let last_ttl_secs = (p.offline_threshold + p.grace_period).as_secs().max(1) as usize;
    let state_ttl_secs = p.state_ttl.as_secs().max(1) as usize;
    // Keep the expiry scheduler aligned with the last_seen key TTL, otherwise
    // entries can be claimed while the key still exists and never be retried.
    let expires_at_ms = now_ms + (p.offline_threshold + p.grace_period).as_millis() as i64;
    let dev_eui_s = dev_eui.to_string();
    let shard = shard_for_dev_eui(dev_eui, p.shards);

    let mut conn = get_async_redis_conn().await?;
    let prev_state: String = Script::new(HEARTBEAT_SCRIPT)
        .key(last_seen_key(shard, &dev_eui_s))
        .key(expiry_key(shard))
        .key(state_key(shard, &dev_eui_s))
        .arg(now_ms)
        .arg(last_ttl_secs)
        .arg(expires_at_ms)
        .arg(&dev_eui_s)
        .arg(state_ttl_secs)
        .invoke_async(&mut conn)
        .await?;

    if prev_state.is_empty() || prev_state == "offline" {
        emit_presence_event(&dev_eui_s, "online").await?;
    }

    Ok(())
}

pub async fn get_last_seen(dev_eui: EUI64) -> Result<Option<chrono::DateTime<Utc>>> {
    let conf = config::get();
    let p = &conf.network.device_presence;
    if !p.enabled {
        return Ok(None);
    }

    let dev_eui_s = dev_eui.to_string();
    let shard = shard_for_dev_eui(dev_eui, p.shards);
    let key = last_seen_key(shard, &dev_eui_s);

    let mut conn = get_async_redis_conn().await?;
    let value: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;

    Ok(value.and_then(|v| parse_last_seen_ts(&v)))
}

pub async fn get_last_seen_many(
    dev_euis: &[EUI64],
) -> Result<HashMap<String, chrono::DateTime<Utc>>> {
    let mut out: HashMap<String, chrono::DateTime<Utc>> = HashMap::new();
    if dev_euis.is_empty() {
        return Ok(out);
    }

    let conf = config::get();
    let p = &conf.network.device_presence;
    if !p.enabled {
        return Ok(out);
    }

    let mut by_shard: HashMap<u32, Vec<String>> = HashMap::new();
    for dev_eui in dev_euis {
        let dev_eui_s = dev_eui.to_string();
        let shard = shard_for_dev_eui(*dev_eui, p.shards);
        by_shard.entry(shard).or_default().push(dev_eui_s);
    }

    let mut conn = get_async_redis_conn().await?;
    for (shard, dev_euis) in by_shard {
        let keys: Vec<String> = dev_euis
            .iter()
            .map(|dev_eui| last_seen_key(shard, dev_eui))
            .collect();

        let values: Vec<Option<String>> =
            redis::cmd("MGET").arg(keys).query_async(&mut conn).await?;
        for (dev_eui, value) in dev_euis.iter().zip(values.into_iter()) {
            if let Some(v) = value.and_then(|ts| parse_last_seen_ts(&ts)) {
                out.insert(dev_eui.clone(), v);
            }
        }
    }

    Ok(out)
}

async fn offline_detector_loop() {
    loop {
        let conf = config::get();
        let p = &conf.network.device_presence;

        if !p.enabled {
            sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        for shard in 0..p.shards.max(1) {
            if let Err(e) = process_shard(shard).await {
                error!(shard, error = %e.full(), "Device presence shard processing error");
            }
        }

        sleep(p.check_interval).await;
    }
}

async fn process_shard(shard: u32) -> Result<()> {
    let conf = config::get();
    let p = &conf.network.device_presence;
    let now_ms = Utc::now().timestamp_millis();

    let mut conn = get_async_redis_conn().await?;
    let due_dev_euis: Vec<String> = Script::new(CLAIM_DUE_SCRIPT)
        .key(expiry_key(shard))
        .arg(now_ms)
        .arg(p.batch_size.max(1))
        .invoke_async(&mut conn)
        .await?;

    if due_dev_euis.is_empty() {
        return Ok(());
    }

    trace!(
        shard,
        count = due_dev_euis.len(),
        "Claimed due device presence entries"
    );

    let state_ttl_secs = p.state_ttl.as_secs().max(1) as usize;
    for dev_eui in due_dev_euis {
        let became_offline: i32 = Script::new(OFFLINE_TRANSITION_SCRIPT)
            .key(last_seen_key(shard, &dev_eui))
            .key(state_key(shard, &dev_eui))
            .arg(state_ttl_secs)
            .invoke_async(&mut conn)
            .await?;

        if became_offline == 1 {
            if let Err(e) = emit_presence_event(&dev_eui, "offline").await {
                warn!(dev_eui = %dev_eui, error = %e.full(), "Emit offline event error");
            }
        }
    }

    Ok(())
}

async fn emit_presence_event(dev_eui: &str, state: &str) -> Result<()> {
    let now = Utc::now();
    let pl = PresenceEvent {
        dev_eui: dev_eui.to_string(),
        state: state.to_string(),
        time_seconds: now.timestamp(),
        time_nanos: now.timestamp_subsec_nanos(),
    };
    let b = serde_json::to_vec(&pl)?;
    stream::event::log_event_for_device(state, dev_eui, &b).await?;
    Ok(())
}

fn shard_for_dev_eui(dev_eui: EUI64, shards: u32) -> u32 {
    if shards <= 1 {
        return 0;
    }

    let v = u64::from_be_bytes(dev_eui.to_be_bytes());
    (v % shards as u64) as u32
}

fn hash_tag(shard: u32) -> String {
    format!("presence:{}", shard)
}

fn expiry_key(shard: u32) -> String {
    let tag = hash_tag(shard);
    redis_key(format!("dev:expiry:{{{}}}", tag))
}

fn last_seen_key(shard: u32, dev_eui: &str) -> String {
    let tag = hash_tag(shard);
    redis_key(format!("dev:last:{{{}}}:{}", tag, dev_eui))
}

fn state_key(shard: u32, dev_eui: &str) -> String {
    let tag = hash_tag(shard);
    redis_key(format!("dev:state:{{{}}}:{}", tag, dev_eui))
}

fn parse_last_seen_ts(v: &str) -> Option<chrono::DateTime<Utc>> {
    let ts_ms: i64 = v.parse().ok()?;
    chrono::DateTime::<Utc>::from_timestamp_millis(ts_ms)
}

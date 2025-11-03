use super::token::CsrfReplayStore;

// no extra trait imports required

/// A Redis-backed CSRF replay store using SET NX with expiration to atomically consume ids.
#[cfg_attr(docsrs, doc(cfg(feature = "csrf-redis")))]
pub struct RedisReplayStore {
    client: redis::Client,
    key_prefix: String,
    ttl_secs: usize,
}

impl RedisReplayStore {
    /// Creates a new Redis-backed replay store.
    /// - `url`: Redis connection URL, e.g., redis://127.0.0.1/ or rediss:// for TLS.
    /// - `key_prefix`: Prefix for keys to avoid collisions (e.g., "csrf:token:").
    /// - `ttl_secs`: Expiration window in seconds; should be at least as long as CSRF token max-age.
    pub fn new(
        url: &str,
        key_prefix: impl Into<String>,
        ttl_secs: usize,
    ) -> redis::RedisResult<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            client,
            key_prefix: key_prefix.into(),
            ttl_secs,
        })
    }

    fn make_key(&self, id: &[u8]) -> String {
        let mut key = String::with_capacity(self.key_prefix.len() + id.len() * 2);
        key.push_str(&self.key_prefix);
        for b in id {
            use core::fmt::Write as _;
            let _ = write!(&mut key, "{:02x}", b);
        }
        key
    }
}

impl CsrfReplayStore for RedisReplayStore {
    fn consume_if_fresh(&self, id: &[u8]) -> bool {
        if id.len() != 16 {
            return false;
        }
        // Best-effort attempt; on Redis error, conservatively return false (treat as replay) to avoid bypass.
        let key = self.make_key(id);
        match self.client.get_connection() {
            Ok(mut conn) => {
                // SET key value NX EX ttl
                let setnx: redis::RedisResult<String> = redis::cmd("SET")
                    .arg(&key)
                    .arg("1")
                    .arg("NX")
                    .arg("EX")
                    .arg(self.ttl_secs)
                    .query(&mut conn);
                matches!(setnx, Ok(reply) if reply == "OK")
            }
            Err(_) => false,
        }
    }
}

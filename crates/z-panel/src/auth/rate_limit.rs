//! Rates for work that is cheap once but costly when repeated: failed
//! sign-ins, API reads, and subscription fetches. Sign-ins are counted only
//! when they fail; reads and fetches count every request in a window. All the
//! tables are bounded, so a flood of different keys cannot grow them forever.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failures an address may make in a window before it is locked.
const MAX_ADDRESS_FAILURES: u32 = 5;
/// Failures against one username, from anywhere, before it is locked.
/// Higher than the address limit: anyone can fail against a username, so a
/// low limit would let a stranger lock the real admin out at will.
const MAX_USERNAME_FAILURES: u32 = 20;
const WINDOW: Duration = Duration::from_secs(15 * 60);
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Keys remembered at most in each table; the oldest are dropped past this,
/// so a flood of addresses, keys or tokens cannot grow a table without bound.
const MAX_KEYS: usize = 10_000;

/// Authenticated reads one session or key may make in a minute. The dashboard
/// polls about thirty times a minute at most; the rest is room for scripts.
pub const READ_LIMIT: u32 = 300;
pub const READ_WINDOW: Duration = Duration::from_secs(60);
/// Subscription fetches from one address in five minutes. A client refreshes
/// its link hours apart; this leaves room for many clients behind one address.
pub const SUBSCRIPTION_LIMIT: u32 = 120;
pub const SUBSCRIPTION_WINDOW: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub struct LoginLimiter {
    entries: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    failures: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

fn keys(address: IpAddr, username: &str) -> [String; 2] {
    [
        format!("ip:{address}"),
        format!("user:{}", username.to_ascii_lowercase()),
    ]
}

impl LoginLimiter {
    /// `Some(seconds)` to wait when this address or username is locked.
    pub fn locked(&self, address: IpAddr, username: &str, now: Instant) -> Option<u64> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        keys(address, username)
            .iter()
            .filter_map(|key| entries.get(key)?.locked_until)
            .filter(|until| *until > now)
            .map(|until| (until - now).as_secs().max(1))
            .max()
    }

    pub fn failed(&self, address: IpAddr, username: &str, now: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if entries.len() >= MAX_KEYS {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.first)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        for key in keys(address, username) {
            let limit = if key.starts_with("ip:") {
                MAX_ADDRESS_FAILURES
            } else {
                MAX_USERNAME_FAILURES
            };
            let entry = entries.entry(key).or_insert(Entry {
                failures: 0,
                first: now,
                locked_until: None,
            });
            if now.duration_since(entry.first) > WINDOW {
                *entry = Entry {
                    failures: 0,
                    first: now,
                    locked_until: None,
                };
            }
            entry.failures += 1;
            if entry.failures >= limit {
                entry.locked_until = Some(now + LOCKOUT);
            }
        }
    }

    /// A successful sign-in forgets the username's failures (not the
    /// address's: one right password does not excuse guessing others).
    pub fn succeeded(&self, username: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.remove(&format!("user:{}", username.to_ascii_lowercase()));
    }
}

/// A fixed window of requests per key, for reads and subscription fetches.
/// Every call counts, unlike [`LoginLimiter`], which counts only mistakes.
pub struct RequestLimiter {
    entries: Mutex<HashMap<String, Window>>,
    limit: u32,
    window: Duration,
}

struct Window {
    used: u32,
    first: Instant,
}

impl RequestLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        assert!(
            limit > 0 && !window.is_zero(),
            "a rate limit needs a window"
        );
        Self {
            entries: Mutex::new(HashMap::new()),
            limit,
            window,
        }
    }

    /// Allow this call, or return the seconds until the key may try again.
    /// Windows are counted from the first call, not sliding with each one, so
    /// the amount of work in any one window stays under `limit`.
    pub fn check(&self, key: &str, now: Instant) -> Option<u64> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        // A full table is the only time sweeping it is worth the work. An
        // unknown key makes room by dropping the oldest window, rather than
        // refusing an otherwise quiet caller.
        if entries.len() >= MAX_KEYS && !entries.contains_key(key) {
            entries.retain(|_, entry| now.saturating_duration_since(entry.first) < self.window);
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.first)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        let entry = entries.entry(key.to_string()).or_insert(Window {
            used: 0,
            first: now,
        });
        if now.saturating_duration_since(entry.first) >= self.window {
            entry.used = 0;
            entry.first = now;
        }
        if entry.used >= self.limit {
            let left = self.window - now.saturating_duration_since(entry.first);
            return Some(left.as_secs().max(1));
        }
        entry.used += 1;
        None
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1));
    const OTHER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 2));

    #[test]
    fn five_failures_lock_the_address() {
        let limiter = LoginLimiter::default();
        let now = Instant::now();
        for _ in 0..4 {
            limiter.failed(HOME, "admin", now);
        }
        assert_eq!(limiter.locked(HOME, "admin", now), None);
        limiter.failed(HOME, "admin", now);
        assert!(limiter.locked(HOME, "admin", now).unwrap() > 800);
        assert!(
            limiter.locked(HOME, "someone", now).is_some(),
            "any name from here"
        );
        // Five failures do not lock the admin out for everyone else.
        assert_eq!(limiter.locked(OTHER, "admin", now), None);
        // And it passes.
        let later = now + LOCKOUT + Duration::from_secs(1);
        assert_eq!(limiter.locked(HOME, "admin", later), None);
    }

    #[test]
    fn many_failures_against_one_username_lock_it_everywhere() {
        let limiter = LoginLimiter::default();
        let now = Instant::now();
        for n in 0..MAX_USERNAME_FAILURES {
            let spread = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, n as u8));
            limiter.failed(spread, "admin", now);
        }
        assert!(limiter.locked(OTHER, "ADMIN", now).is_some());
        assert_eq!(limiter.locked(OTHER, "someone", now), None);
    }

    #[test]
    fn old_failures_age_out_and_success_clears_the_username() {
        let limiter = LoginLimiter::default();
        let now = Instant::now();
        for _ in 0..4 {
            limiter.failed(HOME, "admin", now);
        }
        limiter.failed(HOME, "admin", now + WINDOW + Duration::from_secs(1));
        assert_eq!(
            limiter.locked(HOME, "admin", now + WINDOW + Duration::from_secs(1)),
            None
        );
        limiter.succeeded("admin");
        for _ in 0..4 {
            limiter.failed(OTHER, "admin", now);
        }
        assert_eq!(limiter.locked(OTHER, "admin", now), None);
    }

    #[test]
    fn a_read_window_allows_its_quota_and_then_waits() {
        let limiter = RequestLimiter::new(2, Duration::from_secs(30));
        let now = Instant::now();
        assert_eq!(limiter.check("session:7", now), None);
        assert_eq!(
            limiter.check("session:7", now + Duration::from_secs(1)),
            None
        );
        assert_eq!(
            limiter.check("session:7", now + Duration::from_secs(2)),
            Some(28)
        );
        // Another identity has its own quota, and time resets this one.
        assert_eq!(limiter.check("key:9", now), None);
        assert_eq!(
            limiter.check("session:7", now + Duration::from_secs(30)),
            None
        );
    }

    #[test]
    fn a_flood_of_keys_cannot_grow_the_table() {
        let limiter = RequestLimiter::new(1, Duration::from_secs(30));
        let now = Instant::now();
        for n in 0..MAX_KEYS + 50 {
            assert_eq!(limiter.check(&format!("sub:{n}"), now), None);
            assert!(limiter.len() <= MAX_KEYS, "bounded at every step");
        }
        // An old key may have been dropped, but a new one is still served.
        assert_eq!(limiter.check("sub:new", now), None);
        assert!(limiter.len() <= MAX_KEYS);
    }
}

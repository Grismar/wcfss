use std::collections::HashMap;
use std::time::Instant;

use super::dirindex::DirIndex;

pub type DirCache = HashMap<(u64, u64), DirIndex>;

pub fn evict_if_needed(entries: &mut DirCache, max_entries: usize) {
    if entries.len() <= max_entries {
        return;
    }
    let mut oldest_key: Option<(u64, u64)> = None;
    let mut oldest_at: Option<Instant> = None;
    for (key, value) in entries.iter() {
        if oldest_at.is_none() || value.built_at < oldest_at.unwrap() {
            oldest_at = Some(value.built_at);
            oldest_key = Some(*key);
        }
    }
    if let Some(key) = oldest_key {
        entries.remove(&key);
    }
}

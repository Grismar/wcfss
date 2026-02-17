use std::collections::HashMap;
use std::time::Instant;

use super::dirindex::DirIndex;

pub struct DirIndexCache {
    entries: HashMap<(u64, u64), DirIndex>,
    max_entries: usize,
}

impl DirIndexCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn get_mut(&mut self, key: &(u64, u64)) -> Option<&mut DirIndex> {
        self.entries.get_mut(key)
    }

    pub fn insert(&mut self, index: DirIndex) {
        self.entries.insert(index.dir_id, index);
        self.evict_if_needed();
    }

    pub fn remove(&mut self, key: &(u64, u64)) {
        self.entries.remove(key);
    }

    fn evict_if_needed(&mut self) {
        if self.entries.len() <= self.max_entries {
            return;
        }
        let mut oldest_key: Option<(u64, u64)> = None;
        let mut oldest_at: Option<Instant> = None;
        for (key, value) in self.entries.iter() {
            if oldest_at.is_none() || value.built_at < oldest_at.unwrap() {
                oldest_at = Some(value.built_at);
                oldest_key = Some(*key);
            }
        }
        if let Some(key) = oldest_key {
            self.entries.remove(&key);
        }
    }
}

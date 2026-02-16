use std::collections::HashMap;
use std::time::Instant;

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone)]
pub enum EntrySet {
    Unique(String),
    Ambiguous(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct DirStamp {
    pub dev: u64,
    pub ino: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl DirStamp {
    pub fn matches(&self, other: &DirStamp) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.mtime_sec == other.mtime_sec
            && self.mtime_nsec == other.mtime_nsec
            && self.ctime_sec == other.ctime_sec
            && self.ctime_nsec == other.ctime_nsec
    }
}

impl DirStamp {
    pub fn from_meta(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec() as i64,
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec() as i64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirIndex {
    pub dir_id: (u64, u64),
    pub fold_map: HashMap<String, EntrySet>,
    pub stamp: DirStamp,
    pub built_at: Instant,
    pub dir_index_generation: u64,
}

pub fn insert_entry(map: &mut HashMap<String, EntrySet>, key: String, name: String) -> bool {
    match map.get_mut(&key) {
        None => {
            map.insert(key, EntrySet::Unique(name));
            false
        }
        Some(EntrySet::Unique(existing)) => {
            if existing != &name {
                let mut list = vec![existing.clone(), name];
                list.sort();
                list.dedup();
                *map.get_mut(&key).unwrap() = EntrySet::Ambiguous(list);
                true
            } else {
                false
            }
        }
        Some(EntrySet::Ambiguous(list)) => {
            if !list.iter().any(|entry| entry == &name) {
                list.push(name);
                list.sort();
                list.dedup();
            }
            true
        }
    }
}

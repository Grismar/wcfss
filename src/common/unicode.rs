#![allow(dead_code)]

// Note: uppercase mapping table is generated at build time; further optimizations are optional.
// derived from data/unicode/15.1/UnicodeData.txt so we don't parse text at runtime.

#[derive(Debug, Default, Clone)]
pub struct UnicodeTables;

impl UnicodeTables {
    pub fn new() -> Self {
        Self
    }
}

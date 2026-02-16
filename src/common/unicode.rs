#![allow(dead_code)]

// TODO(unicode): Build and store a binary/efficient uppercase mapping table
// derived from data/unicode/15.1/UnicodeData.txt so we don't parse text at runtime.

#[derive(Debug, Default, Clone)]
pub struct UnicodeTables;

impl UnicodeTables {
    pub fn new() -> Self {
        Self
    }
}

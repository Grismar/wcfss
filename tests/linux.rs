#![cfg(target_os = "linux")]

mod parser {
    include!("linux/parser.rs");
}
mod resolver {
    include!("linux/resolver.rs");
}

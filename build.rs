use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=data/unicode/15.1/UnicodeData.txt");

    let src = PathBuf::from("data/unicode/15.1/UnicodeData.txt");
    let file = File::open(&src).expect("open UnicodeData.txt");
    let reader = BufReader::new(file);

    let mut map: Vec<u32> = (0..0x110000).collect();

    for line in reader.lines() {
        let line = line.expect("read UnicodeData.txt line");
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(';');
        let code_hex = fields.next().expect("codepoint field");
        let code = u32::from_str_radix(code_hex, 16).expect("parse codepoint");

        let mut simple_upper: Option<&str> = None;
        for (idx, field) in fields.enumerate() {
            if idx == 11 {
                if !field.is_empty() {
                    simple_upper = Some(field);
                }
                break;
            }
        }

        if let Some(upper_hex) = simple_upper {
            let upper =
                u32::from_str_radix(upper_hex, 16).expect("parse simple uppercase mapping");
            map[code as usize] = upper;
        }
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("unicode15_1_upper.rs");
    let mut out = File::create(&dest).expect("create unicode15_1_upper.rs");

    writeln!(
        out,
        "pub static SIMPLE_UPPERCASE_MAP: [u32; 0x110000] = ["
    )
    .expect("write map header");

    for (i, value) in map.iter().enumerate() {
        if i % 8 == 0 {
            write!(out, "    ").expect("write indent");
        }
        write!(out, "0x{:X}, ", value).expect("write value");
        if i % 8 == 7 {
            writeln!(out).expect("write newline");
        }
    }
    if map.len() % 8 != 0 {
        writeln!(out).expect("write trailing newline");
    }
    writeln!(out, "];").expect("write map footer");
}

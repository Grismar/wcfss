use crate::common::types::ResolverStatus;

include!(concat!(env!("OUT_DIR"), "/unicode15_1_upper.rs"));

const MAX_INPUT_PATH_BYTES: usize = 32 * 1024;
const MAX_COMPONENTS: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootKind {
    Relative,
    PosixRoot,
    Drive(char),
    Unc { server: String, share: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPath {
    pub root: RootKind,
    pub components: Vec<String>,
    pub had_backslash: bool,
}

pub fn key_simple_uppercase(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let mapped = SIMPLE_UPPERCASE_MAP[ch as usize];
        if let Some(c) = char::from_u32(mapped) {
            out.push(c);
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn parse_path_bytes(input: &[u8]) -> Result<ParsedPath, ResolverStatus> {
    if input.len() > MAX_INPUT_PATH_BYTES {
        return Err(ResolverStatus::PathTooLong);
    }
    let input_str = std::str::from_utf8(input).map_err(|_| ResolverStatus::EncodingError)?;
    parse_path_str(input_str)
}

pub fn parse_path_str(input: &str) -> Result<ParsedPath, ResolverStatus> {
    if input.len() > MAX_INPUT_PATH_BYTES {
        return Err(ResolverStatus::PathTooLong);
    }

    let mut normalized = String::with_capacity(input.len());
    let mut had_backslash = false;
    for ch in input.chars() {
        if ch == '\\' {
            had_backslash = true;
            normalized.push('/');
        } else {
            normalized.push(ch);
        }
    }

    if normalized.starts_with("//") {
        let mut parts = normalized[2..].split('/').filter(|p| !p.is_empty());
        let server = parts.next().ok_or(ResolverStatus::InvalidPath)?;
        let share = parts.next().ok_or(ResolverStatus::InvalidPath)?;
        let components = parse_components_iter(parts, true)?;
        return Ok(ParsedPath {
            root: RootKind::Unc {
                server: server.to_string(),
                share: share.to_string(),
            },
            components,
            had_backslash,
        });
    }

    let (root, remainder) = parse_root(&normalized)?;
    let components = parse_components_iter(remainder.split('/'), root_is_absolute(&root))?;

    Ok(ParsedPath {
        root,
        components,
        had_backslash,
    })
}

fn root_is_absolute(root: &RootKind) -> bool {
    matches!(root, RootKind::PosixRoot | RootKind::Drive(_) | RootKind::Unc { .. })
}

fn parse_root(input: &str) -> Result<(RootKind, &str), ResolverStatus> {
    let bytes = input.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        if bytes.len() == 2 {
            return Err(ResolverStatus::InvalidPath);
        }
        let next = bytes[2] as char;
        if next != '/' {
            return Err(ResolverStatus::InvalidPath);
        }
        let drive = (bytes[0] as char).to_ascii_uppercase();
        let remainder = &input[3..];
        return Ok((RootKind::Drive(drive), remainder));
    }

    if input.starts_with('/') {
        let remainder = input.trim_start_matches('/');
        return Ok((RootKind::PosixRoot, remainder));
    }

    Ok((RootKind::Relative, input))
}

fn parse_components_iter<'a, I>(iter: I, is_absolute: bool) -> Result<Vec<String>, ResolverStatus>
where
    I: Iterator<Item = &'a str>,
{
    let mut components: Vec<String> = Vec::new();
    for part in iter {
        if part.is_empty() {
            continue;
        }
        if part == "." {
            continue;
        }
        if part == ".." {
            if components.is_empty() && is_absolute {
                return Err(ResolverStatus::EscapesRoot);
            }
            if components.is_empty() && !is_absolute {
                return Err(ResolverStatus::EscapesRoot);
            }
            components.pop();
            continue;
        }
        if part.as_bytes().len() > MAX_COMPONENT_BYTES {
            return Err(ResolverStatus::PathTooLong);
        }
        components.push(part.to_string());
        if components.len() > MAX_COMPONENTS {
            return Err(ResolverStatus::PathTooLong);
        }
    }

    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_simple_uppercase_basic() {
        assert_eq!(key_simple_uppercase("abcXYZ"), "ABCXYZ");
        assert_eq!(key_simple_uppercase("mañana"), "MAÑANA");
        assert_eq!(key_simple_uppercase("føø"), "FØØ");
        assert_eq!(key_simple_uppercase("ß"), "ẞ");
    }

    #[test]
    fn empty_and_dot_paths() {
        let parsed = parse_path_str("").unwrap();
        assert_eq!(parsed.root, RootKind::Relative);
        assert!(parsed.components.is_empty());

        let parsed = parse_path_str(".").unwrap();
        assert_eq!(parsed.root, RootKind::Relative);
        assert!(parsed.components.is_empty());

        let parsed = parse_path_str("././.").unwrap();
        assert_eq!(parsed.root, RootKind::Relative);
        assert!(parsed.components.is_empty());
    }

    #[test]
    fn separator_normalization() {
        let parsed = parse_path_str("a\\b/c").unwrap();
        assert_eq!(parsed.components, vec!["a", "b", "c"]);
        assert!(parsed.had_backslash);

        let parsed = parse_path_str("a//b///c").unwrap();
        assert_eq!(parsed.components, vec!["a", "b", "c"]);
    }

    #[test]
    fn dotdot_reduction() {
        let parsed = parse_path_str("a/b/../c").unwrap();
        assert_eq!(parsed.components, vec!["a", "c"]);

        let err = parse_path_str("../c").unwrap_err();
        assert_eq!(err, ResolverStatus::EscapesRoot);
    }

    #[test]
    fn absolute_root_and_dotdot() {
        let parsed = parse_path_str("/a/../b").unwrap();
        assert_eq!(parsed.root, RootKind::PosixRoot);
        assert_eq!(parsed.components, vec!["b"]);

        let err = parse_path_str("/../b").unwrap_err();
        assert_eq!(err, ResolverStatus::EscapesRoot);
    }

    #[test]
    fn drive_paths() {
        let parsed = parse_path_str("C:\\foo\\bar").unwrap();
        assert_eq!(parsed.root, RootKind::Drive('C'));
        assert_eq!(parsed.components, vec!["foo", "bar"]);

        let err = parse_path_str("C:foo").unwrap_err();
        assert_eq!(err, ResolverStatus::InvalidPath);
    }

    #[test]
    fn unc_paths() {
        let parsed = parse_path_str("\\\\server\\share\\dir\\file").unwrap();
        assert_eq!(
            parsed.root,
            RootKind::Unc {
                server: "server".to_string(),
                share: "share".to_string()
            }
        );
        assert_eq!(parsed.components, vec!["dir", "file"]);

        let err = parse_path_str("\\\\server").unwrap_err();
        assert_eq!(err, ResolverStatus::InvalidPath);
    }

    #[test]
    fn invalid_utf8_rejected() {
        let err = parse_path_bytes(&[0xff, 0xfe]).unwrap_err();
        assert_eq!(err, ResolverStatus::EncodingError);
    }

    #[test]
    fn component_limits_enforced() {
        let long_component = "a".repeat(MAX_COMPONENT_BYTES + 1);
        let err = parse_path_str(&long_component).unwrap_err();
        assert_eq!(err, ResolverStatus::PathTooLong);

        let mut input = String::new();
        for i in 0..(MAX_COMPONENTS + 1) {
            if i > 0 {
                input.push('/');
            }
            input.push_str("a");
        }
        let err = parse_path_str(&input).unwrap_err();
        assert_eq!(err, ResolverStatus::PathTooLong);
    }

    #[test]
    fn total_length_limit_enforced() {
        let input = "a".repeat(MAX_INPUT_PATH_BYTES + 1);
        let err = parse_path_str(&input).unwrap_err();
        assert_eq!(err, ResolverStatus::PathTooLong);
    }
}

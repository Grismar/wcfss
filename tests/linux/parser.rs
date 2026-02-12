use wcfss::linux_emulation::parser::{
    key_simple_uppercase, parse_path_bytes, parse_path_str, RootKind,
};
use wcfss::ResolverStatus;

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
    let long_component = "a".repeat(256);
    let err = parse_path_str(&long_component).unwrap_err();
    assert_eq!(err, ResolverStatus::PathTooLong);

    let mut input = String::new();
    for i in 0..(4096 + 1) {
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
    let input = "a".repeat((32 * 1024) + 1);
    let err = parse_path_str(&input).unwrap_err();
    assert_eq!(err, ResolverStatus::PathTooLong);
}

use super::*;
use crate::tests_common as common;

#[test]
fn given_headers_with_control_characters_when_execute_then_sanitizes_values() {
    let mut headers = NormalizedHeaders::new(common::headers_with(&[
        ("Permissions-Policy", "camera=()\r\ngeolocation=()"),
        ("X-Test", "value\u{0008}two"),
    ]));
    let executor = SafeHeaders::new();

    executor.execute(&mut headers).expect("execute");

    let result = headers.into_result();

    assert_eq!(
        result.get("Permissions-Policy").map(String::as_str),
        Some("camera=() geolocation=()"),
    );
    assert_eq!(result.get("X-Test").map(String::as_str), Some("value two"));
}

#[test]
fn given_headers_without_control_characters_when_execute_then_preserves_values() {
    let mut headers = NormalizedHeaders::new(common::headers_with(&[("X-Test", "value")]));
    let executor = SafeHeaders::new();

    executor.execute(&mut headers).expect("execute");

    let result = headers.into_result();

    assert_eq!(result.get("X-Test").map(String::as_str), Some("value"));
}

#[test]
fn given_set_cookie_with_injected_newline_when_execute_then_sanitizes_segment() {
    let mut headers = NormalizedHeaders::new(common::headers_with(&[(
        "Set-Cookie",
        "session=one\nSet-Cookie: token=two\r\nSet-Cookie: admin=yes",
    )]));
    let executor = SafeHeaders::new();

    executor.execute(&mut headers).expect("execute");

    let result = headers.into_result();
    let cookie = result.get("Set-Cookie").expect("set-cookie header");

    assert_eq!(
        cookie, "session=one\ntoken=two\nadmin=yes",
        "sanitization should remove header injection markers while keeping values",
    );
}

//! Header-based format detection and the name rules: no input may crash
//! them, and escaped text may never contain a character unsafe to display.

#![no_main]

use libfuzzer_sys::fuzz_target;
use trustforge_core::format::detect_format;
use trustforge_core::name::{
    EscapedBytes, is_unsafe_to_display, validate_name, validate_symlink_target,
};

fuzz_target!(|data: &[u8]| {
    let _ = detect_format(data);
    if let Ok(name) = validate_name(data) {
        assert!(
            !name
                .chars()
                .any(|c| is_unsafe_to_display(c) || c == '/' || c == '\\')
        );
    }
    if let Ok(target) = validate_symlink_target(data) {
        assert!(!target.chars().any(|c| is_unsafe_to_display(c) || c == '\\'));
    }
    assert!(
        !EscapedBytes(data)
            .to_string()
            .chars()
            .any(is_unsafe_to_display)
    );
});

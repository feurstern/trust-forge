//! Strict JSON and manifest parsing: no input may crash them, and whatever
//! they accept must survive being written and read again unchanged.

#![no_main]

use libfuzzer_sys::fuzz_target;
use trustforge_core::json::{self, JsonLimits};
use trustforge_core::manifest::{ParseOptions, parse_manifest};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = json::parse(data, &JsonLimits::default()) {
        // The indented form can exceed the size limit the input met.
        let mut unlimited = JsonLimits::default();
        unlimited.max_bytes = usize::MAX;
        let canonical = json::to_canonical(&value);
        assert_eq!(json::parse(&canonical, &unlimited).as_ref(), Ok(&value));
        let pretty =
            json::parse(&json::to_pretty(&value), &unlimited).expect("the indented form parses");
        assert_eq!(json::to_canonical(&pretty), canonical);
    }
    if let Ok(parsed) = parse_manifest(data, &ParseOptions::default()) {
        let mut opts = ParseOptions::default();
        opts.limits.max_bytes = usize::MAX;
        let rewritten = parse_manifest(&parsed.manifest.to_canonical_json(), &opts)
            .expect("a written manifest parses");
        assert_eq!(rewritten.manifest, parsed.manifest);
    }
});

//! The report reader: no input may crash it, and whatever it accepts must be
//! written back and read again unchanged, in both forms.

#![no_main]

use libfuzzer_sys::fuzz_target;
use trustforge_core::json::JsonLimits;
use trustforge_core::report::read_report;

fuzz_target!(|data: &[u8]| {
    if let Ok(report) = read_report(data, &JsonLimits::default()) {
        // The indented form can exceed the size limit the input met.
        let mut unlimited = JsonLimits::default();
        unlimited.max_bytes = usize::MAX;
        let canonical = read_report(&report.to_canonical_json(), &unlimited)
            .expect("a written report reads back");
        assert_eq!(canonical, report);
        let pretty = read_report(&report.to_pretty_json(), &unlimited)
            .expect("the indented form reads back");
        assert_eq!(pretty, report);
    }
});

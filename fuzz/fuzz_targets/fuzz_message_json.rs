#![no_main]
//! Fuzz the per-message attachment JSON parser: arbitrary bytes in, never a
//! panic (malformed/adversarial JSON yields an empty attachment list).

use libfuzzer_sys::fuzz_target;
use signal_desktop_core::store::parse_attachments_json;

fuzz_target!(|data: &[u8]| {
    let json = String::from_utf8_lossy(data);
    let _ = parse_attachments_json("fuzz", &json);
});

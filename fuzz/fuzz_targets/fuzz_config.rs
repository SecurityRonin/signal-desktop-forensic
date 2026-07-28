#![no_main]
//! Fuzz the `config.json` parser: arbitrary bytes in, never a panic.

use libfuzzer_sys::fuzz_target;
use signal_desktop_core::config::SignalConfig;

fuzz_target!(|data: &[u8]| {
    // Malformed JSON / bad hex / missing fields must all be typed errors,
    // never a panic.
    let _ = SignalConfig::from_bytes(data);
});

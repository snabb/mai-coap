#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| mai_coap_fuzz::client_transfer(data));

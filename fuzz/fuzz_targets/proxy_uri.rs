#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| mai_coap_fuzz::proxy_uri(data));

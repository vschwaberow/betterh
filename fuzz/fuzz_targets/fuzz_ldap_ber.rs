#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    betterh::protocols::fuzz_api::ldap_ber(data);
});

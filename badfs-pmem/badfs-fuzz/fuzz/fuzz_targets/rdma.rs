#![no_main]
use libfuzzer_sys::fuzz_target;
use badfs_fuzz::*;
fuzz_target!(|data: [ClientOperations;1023]| {
    test_client(&data);
});

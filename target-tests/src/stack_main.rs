#![no_std]
#![no_main]

use cortex_m as _;
use cortex_m_rt::entry;
// Keep the RNG at crate root for concrete names in the storage-layout report.
include!("rng.rs");
mod stack;

#[entry]
fn main() -> ! {
    stack::run();
    semihosting::println!("mai-coap target runtime: PASS");
    semihosting::process::exit(0)
}

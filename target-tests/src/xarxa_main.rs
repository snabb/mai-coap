#![no_std]
#![no_main]

use cortex_m as _;
use cortex_m_rt::entry;
include!("rng.rs");
mod xarxa_fixture;

#[entry]
fn main() -> ! {
    xarxa_fixture::run();
    semihosting::println!("mai-coap xarxa runtime: PASS");
    semihosting::process::exit(0)
}

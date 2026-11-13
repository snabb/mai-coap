use std::{env, fs, path::PathBuf};

fn main() {
    let target = env::var("TARGET").unwrap();
    println!("cargo:rustc-check-cfg=cfg(small_ram)");
    if target == "thumbv6m-none-eabi" {
        println!("cargo:rustc-cfg=small_ram");
    }
    if env::var_os("CARGO_FEATURE_STACK_PROFILE").is_some() {
        assert!(
            matches!(
                target.as_str(),
                "thumbv7em-none-eabihf" | "thumbv8m.main-none-eabihf"
            ),
            "stack-profile supports Cortex-M4 and Cortex-M33 only"
        );
    }
    let memory = match target.as_str() {
        "thumbv6m-none-eabi" => {
            "MEMORY { FLASH : ORIGIN = 0, LENGTH = 256K\n RAM : ORIGIN = 0x20000000, LENGTH = 16K }"
        }
        "thumbv7em-none-eabihf" => {
            "MEMORY { FLASH : ORIGIN = 0, LENGTH = 1024K\n RAM : ORIGIN = 0x20000000, LENGTH = 128K }"
        }
        // Multi-driver resource fixtures use the model's 2 MiB SSRAM1 secure
        // alias. Ordinary runtime fixtures retain the 32 KiB internal SRAM.
        "thumbv8m.main-none-eabihf"
            if env::var_os("CARGO_FEATURE_STACK_PROFILE").is_some()
                || env::var_os("CARGO_FEATURE_XARXA_PROFILE").is_some()
                || env::var_os("CARGO_FEATURE_PROXY_PROFILE").is_some() =>
        {
            "MEMORY { FLASH : ORIGIN = 0x10000000, LENGTH = 4M\n RAM : ORIGIN = 0x38000000, LENGTH = 128K }"
        }
        "thumbv8m.main-none-eabihf" => {
            "MEMORY { FLASH : ORIGIN = 0x10000000, LENGTH = 4M\n RAM : ORIGIN = 0x30000000, LENGTH = 32K }"
        }
        // Leave QEMU room above the image for its generated device tree.
        "riscv32imac-unknown-none-elf" => {
            "MEMORY { RAM : ORIGIN = 0x80000000, LENGTH = 16M }\nREGION_ALIAS(\"REGION_TEXT\", RAM);\nREGION_ALIAS(\"REGION_RODATA\", RAM);\nREGION_ALIAS(\"REGION_DATA\", RAM);\nREGION_ALIAS(\"REGION_BSS\", RAM);\nREGION_ALIAS(\"REGION_HEAP\", RAM);\nREGION_ALIAS(\"REGION_STACK\", RAM);"
        }
        _ => panic!("unsupported runtime-test target: {target}"),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(output.join("memory.x"), memory).unwrap();
    println!("cargo:rustc-link-search={}", output.display());
    if target.starts_with("riscv") {
        println!("cargo:rustc-link-arg=-Tmemory.x");
    }
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=build.rs");
}

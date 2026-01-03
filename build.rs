fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_arch == "wasm32" {
        if target_os == "wasi" {
            println!("cargo::rustc-cfg=wasm_wasi");
        } else {
            println!("cargo::rustc-cfg=wasm_browser");
        }
    } else {
        println!("cargo::rustc-cfg=native");
    }
}

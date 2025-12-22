use openssl::version;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(openssl111)");

    let version = version::version();
    if version.starts_with("OpenSSL ") {
        if version::number() >= 0x1_01_01_00_0 {
            println!("cargo:rustc-cfg=openssl111");
        }
    }
}

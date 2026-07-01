fn main() {
    println!("cargo:rustc-link-lib=dylib=capi10");
    println!("cargo:rustc-link-lib=dylib=capi20");
    println!("cargo:rustc-link-lib=dylib=rdrsup");
    println!("cargo:rustc-link-search=/opt/cprocsp/lib/amd64");
}

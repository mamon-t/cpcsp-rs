fn main() {
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=crypt32");
    
    // CryptoPro специфичные функции (CPCrypt*, CPGet*)
    // Раскомментируйте нужное в зависимости от установленной версии КриптоПро:
    // println!("cargo:rustc-link-lib=cpcsp");
    // println!("cargo:rustc-link-lib=capilite");
}
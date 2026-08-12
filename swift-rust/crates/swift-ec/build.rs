// Link the system liberasurecode shared library (the same codec Python's
// PyECLib uses, so fragments are byte-identical). The library is expected in
// the standard search path (e.g. /usr/lib64/liberasurecode.so on Rocky/RHEL);
// an extra hint path can be given via LIBERASURECODE_LIB_DIR.
fn main() {
    if let Ok(dir) = std::env::var("LIBERASURECODE_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
    }
    for dir in [
        "/usr/lib64",
        "/usr/local/lib64",
        "/usr/local/lib",
        "/usr/lib",
    ] {
        if std::path::Path::new(dir).join("liberasurecode.so").exists()
            || std::path::Path::new(dir)
                .join("liberasurecode.so.1")
                .exists()
        {
            println!("cargo:rustc-link-search=native={dir}");
        }
    }
    println!("cargo:rustc-link-lib=dylib=erasurecode");
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-container-info <path>");
        std::process::exit(1);
    });
    match swift_cli::info::container_info(std::path::Path::new(&path)) {
        Ok(out) => print!("{}", out),
        Err(e) => { eprintln!("{}", e); std::process::exit(1); }
    }
}

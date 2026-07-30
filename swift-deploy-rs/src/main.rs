fn main() {
    if let Err(error) = swift_deploy_rs::cli::run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

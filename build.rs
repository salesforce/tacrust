use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("hello.rs");
    fs::write(
        dest_path,
        "pub fn message() -> &'static str {
            \"Hello, World!\"
        }
        ",
    )
    .unwrap();

    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    let dest_path = Path::new(&out_dir).join("version.txt");
    fs::write(dest_path, format!("{:?}", env::var("FULL_VERSION"))).unwrap();
    if env::var("FULL_VERSION").is_err() {
        println!("cargo:rustc-env=FULL_VERSION=dev-{}", git_hash);
    }

    println!("cargo:rerun-if-changed=build.rs");
}

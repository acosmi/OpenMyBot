use std::{path::PathBuf, process::Command};

fn git(args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .output()
        .expect("git required");
    assert!(output.status.success(), "git metadata unavailable");
    String::from_utf8(output.stdout)
        .expect("git metadata UTF-8")
        .trim()
        .to_owned()
}

fn main() {
    let head = git(&["rev-parse", "HEAD"]);
    assert!(
        head.len() == 40
            && head
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid engine pin"
    );
    println!("cargo:rustc-env=OMB_ENGINE_PIN={head}");
    let git_dir = PathBuf::from(git(&["rev-parse", "--absolute-git-dir"]));
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    let reference = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        .expect("git required");
    if reference.status.success() {
        let name = String::from_utf8(reference.stdout).expect("ref UTF-8");
        let path = git(&["rev-parse", "--git-path", name.trim()]);
        println!("cargo:rerun-if-changed={path}");
    }
    let packed = git(&["rev-parse", "--git-path", "packed-refs"]);
    println!("cargo:rerun-if-changed={packed}");
}

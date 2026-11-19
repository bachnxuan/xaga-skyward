fn main() {
    println!("cargo:rerun-if-changed=policy.c");
    let sepol = pkg_config::Config::new()
        .atleast_version("3.11")
        .statik(true)
        .cargo_metadata(false)
        .probe("libsepol")
        .expect("libsepol 3.11 or newer is required to preserve Android policy features");
    cc::Build::new()
        .file("policy.c")
        .includes(&sepol.include_paths)
        .std("gnu11")
        .compile("skyward_policy");
    for path in &sepol.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    println!("cargo:rustc-link-lib=static=sepol");
}

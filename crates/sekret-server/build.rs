// The web interface is embedded from web/dist at compile time. Without this, a build made
// before web/dist existed is reused after the interface is built, and ships without it.
fn main() {
    println!("cargo:rerun-if-changed=../../web/dist");
    println!("cargo:rerun-if-changed=build.rs");
}

//! Pure domain logic for sekret: crypto, permissions, validation and claim binding.

pub mod claims;
pub mod crypto;
pub mod glob;
pub mod permissions;
pub mod rotation;
pub mod seal;
pub mod validate;

/// The release version, set by the release workflow through `RELEASE_VERSION`, or the crate
/// version in local builds.
pub const VERSION: &str = match option_env!("RELEASE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[cfg(test)]
mod tests {
    #[test]
    fn version_falls_back_to_the_crate_version() {
        assert!(!super::VERSION.is_empty());
        match option_env!("RELEASE_VERSION") {
            Some(release) => assert_eq!(super::VERSION, release),
            None => assert_eq!(super::VERSION, env!("CARGO_PKG_VERSION")),
        }
    }
}

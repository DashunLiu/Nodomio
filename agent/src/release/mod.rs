pub mod binding;
pub mod github;
pub mod manifest;

#[cfg(test)]
pub(crate) mod github_tests;

#[cfg(all(test, target_os = "linux"))]
mod handoff_tests;

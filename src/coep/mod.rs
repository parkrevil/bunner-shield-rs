mod executor;
mod options;

pub use executor::Coep;
pub use options::{CoepOptions, CoepOptionsError, CoepPolicy};

#[cfg(test)]
#[path = "mod_test.rs"]
mod mod_test;

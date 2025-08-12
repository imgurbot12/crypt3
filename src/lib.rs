//! Temp

#![warn(missing_docs)]

mod encode;
mod internal;
mod parse;
mod random;
mod traits;

pub mod crypt;
pub mod error;

pub use traits::{FindNul, IntoHashSetup};

/// Setup struct for basic hashing customization.
///
/// All implemented hash functions accept a custom salt value. If set to `None`,
/// a random salt will be generated. The usage of `rounds` varies with the
/// algorithm; visit the algorithm's module-level documentation for details.
/// It's always safe to initialize `rounds` to `None`, in which case the suitable
/// default value will be used.
#[derive(Default)]
pub struct HashSetup<'a> {
    /// Custom salt.
    pub salt: Option<&'a str>,
    /// Number of rounds.
    pub rounds: Option<u32>,
}

impl<'a> HashSetup<'a> {
    /// Configure custom salt for hash algorithm
    pub fn salt(mut self, salt: &'a str) -> Self {
        self.salt = Some(salt);
        self
    }
    /// Configure custom number of rounds for hash algorithm
    pub fn rounds(mut self, rounds: u32) -> Self {
        self.rounds = Some(rounds);
        self
    }
}

#[inline]
pub(crate) fn consteq(hash: &str, calchash: error::Result<String>) -> bool {
    calchash.ok().map(|hstr| hash == hstr).unwrap_or_default()
}

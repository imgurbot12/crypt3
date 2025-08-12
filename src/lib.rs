//! A collection of password hashing and verification routines.
//!
//! # Examples
//!
//! To verify a password hashed with a known algorithm:
//!
//! ```
//! use crypt3_rs::crypt::bcrypt;
//!
//! let h = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
//! assert_eq!(bcrypt::verify("password", h), true);
//! ```
//!
//! To hash a password using default parameters:
//!
//! ```
//! use crypt3_rs::crypt::bcrypt;
//!
//! let h = bcrypt::hash("password").unwrap();
//! ```
//!
//! To verify a password known to be in one of Unix modular hash formats:
//!
//! ```
//! use crypt3_rs::unix;
//!
//! let h = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
//! assert_eq!(unix::verify("password", h), true);
//! ```
//!
//! # Summary
//!
//! Currently, there are implementations of seven algorithms, which should
//! cover anything one might find as a system-wide hash on a free Unix-like
//! OS: [bcrypt](crypt::bcrypt), [SHA-512](crypt::sha512), [SHA-256](crypt::sha256),
//! [HMAC-SHA1](crypt::sha1), [MD5](crypt::md5), [BSDi crypt](crypt::bsdi), and
//! [DES crypt](crypt::unix). The list is ordered roughly by security, with the
//! most secure algorithms first. The first two are recommended for new
//! passwords.
//!
//! Each algorithm is implemented in its own module, and offers three ways of
//! using it:
//!
//! * The `verify` function checks whether the provided hash corresponds to a
//!   password.
//!
//! * The `hash` function hashes a password using the default parameters for the
//!   algorithm.
//!
//! * The `hash_with` function allows the caller to customize the hashing
//!   parameters.
//!
//! Customization can always be accomplished by passing a `&str` with encoded
//! parameters (in the appropriate hash format) to `hash_with`. All algorithms
//! except DES crypt accept a `HashSetup` struct as a means of customization,
//! while bcrypt also has its own setup structure (see the module documenation.)
//!
//! The [unix] module provides a __crypt__(3)-compatible function and a
//! `verify` which uses it to automatically recognize the algorithm of the
//! provided hash.

#![warn(missing_docs)]

mod encode;
mod hash;
mod internal;
mod parse;
mod random;
mod traits;

pub mod crypt;
pub mod error;

pub use hash::Hash;
pub use traits::{FindNul, IntoHashSetup};

#[inline]
pub(crate) fn consteq(hash: &str, calchash: error::Result<Hash>) -> bool {
    calchash
        .ok()
        .map(|hstr| hash == hstr.as_str())
        .unwrap_or_default()
}

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

pub mod unix {
    //! Convenience functions for Unix modular hashes.
    //!
    //! If it's known that a hash is in one of the supported modular hash formats,
    //! the functions in this module can be used to verify or re-calculate the
    //! hash.
    use crate::{Hash, consteq, error::Result};

    /// A Unix __crypt__(3) work-alike.
    #[inline]
    pub fn crypt<B: AsRef<[u8]>>(pass: B, hash: &str) -> Result<Hash> {
        Hash::try_from(hash)?.hash_with(pass)
    }

    /// Verify that the hash corresponds to a password, using hash format recognition.
    pub fn verify<B: AsRef<[u8]>>(pass: B, hash: &str) -> bool {
        consteq(hash, crypt(pass, hash))
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn crypt_recognized() {
            assert_eq!(
                super::crypt("password", "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0").unwrap(),
                "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0"
            );
            assert_eq!(
                super::crypt("test", "aZGJuE6EXrjEE").unwrap(),
                "aZGJuE6EXrjEE"
            );
        }
    }
}

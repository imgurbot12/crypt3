//! Supported password hashing and verification algorithms.

#[cfg(all(feature = "apr1", not(feature = "md5")))]
mod md5;

#[cfg(feature = "md5")]
pub mod md5;

#[cfg(feature = "apr1")]
pub mod apr1;

#[cfg(feature = "bcrypt")]
pub mod bcrypt;

#[cfg(feature = "bsdi")]
pub mod bsdi;

#[cfg(feature = "sha1")]
pub mod sha1;

#[cfg(feature = "sha2")]
pub mod sha256;

#[cfg(feature = "sha2")]
pub mod sha512;

#[cfg(feature = "unix")]
pub mod unix;

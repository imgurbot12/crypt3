use crate::{error::Result, HashSetup};

/// A trait for converting a type into a `HashSetup` struct.
pub trait IntoHashSetup<'a> {
    /// The conversion function.
    fn into_hash_setup(self, f: fn(&'a str) -> Result<HashSetup<'a>>) -> Result<HashSetup<'a>>;
}

impl<'a> IntoHashSetup<'a> for &'a str {
    fn into_hash_setup(self, f: fn(&'a str) -> Result<HashSetup<'a>>) -> Result<HashSetup<'a>> {
        f(self)
    }
}

impl<'a> IntoHashSetup<'a> for HashSetup<'a> {
    fn into_hash_setup(self, _f: fn(&'a str) -> Result<HashSetup<'a>>) -> Result<HashSetup<'a>> {
        Ok(self)
    }
}

/// A trait for extracting a NUL-terminated subslice from a slice.
///
/// The original Unix hashing functions expect passwords to be NUL-terminated C strings. This
/// allows values which can't be represented by Rust strings, which are constrained to be UTF-8.
/// On the other hand, Rust strings can contain NUL bytes, and C strings can't.
///
/// For maximum flexibility, hashing functions in this crate accept both strings and raw byte
/// vectors as password input. This trait can be used to ensure that any input value will be
/// truncated at the first NUL byte.
pub trait FindNul {
    /// Subslice extraction function.
    ///
    /// Given a slice, find and return the subslice before the first NUL byte, or the original
    /// slice if no NUL byte is found. Before searching, the slice is converted into a byte
    /// slice, if necessary. The returned slice also consists of raw bytes.
    fn nul_terminated_subslice(&self) -> &[u8];
}

impl FindNul for str {
    fn nul_terminated_subslice(&self) -> &[u8] {
        let nul_pos = self
            .as_bytes()
            .windows(1)
            .position(|window| window == [0u8])
            .unwrap_or(self.len());
        &self.as_bytes()[..nul_pos]
    }
}

impl FindNul for [u8] {
    fn nul_terminated_subslice(&self) -> &[u8] {
        let nul_pos = self
            .windows(1)
            .position(|window| window == [0u8])
            .unwrap_or(self.len());
        self[..nul_pos].as_ref()
    }
}

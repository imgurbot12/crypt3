//! MD5 based hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! This algorithm was developed for FreeBSD to replace the
//! aging DES crypt. It was adopted in various Linux distributions
//! and saw wide use. Presently, it's considered insecure and
//! shouldn't be used for new passwords.
//!
//! # Example
//!
//! ```
//! use pwhash::apr1_crypt;
//!
//! assert_eq!(apr1_crypt::hash_with(
//!     "$apr1$63JlJ2NH$smE0mnB5h3tDri0zkpWXt1",
//!     "password").unwrap(),
//!     "$apr1$63JlJ2NH$smE0mnB5h3tDri0zkpWXt1");
//! ```
//!
//! # Parameters
//!
//! * __Password length__: unlimited.
//!
//! * __Salt length__: 0 to 8 characters. Default is 8.
//!
//! * __Rounds__: 1000 (fixed.)
//!
//! # Hash Format
//!
//! The format of the hash is
//! __`$1$`__*`{salt}`*__$__*`{checksum}`*, where:
//!
//! * *`{salt}`* is the salt string.
//!
//! * *`{checksum}`* is a 22-character Base64 encoding of the checksum.

use super::{consteq, HashSetup, IntoHashSetup, Result};
use crate::error::Error;
use crate::md5_crypt::do_md5_crypt;
use crate::parse::{self, HashIterator};
use crate::random;

/// Maximium salt length.
pub const MAX_SALT_LEN: usize = 8;
const APR1_MAGIC: &str = "$apr1$";

/// Hash a password with a randomly generated salt.
///
/// An error is returned if the system random number generator cannot
/// be opened.
#[deprecated(since = "0.2.0", note = "don't use this algorithm for new passwords")]
pub fn hash<B: AsRef<[u8]>>(pass: B) -> Result<String> {
    let saltstr = random::gen_salt_str(MAX_SALT_LEN);
    do_md5_crypt(pass.as_ref(), &saltstr, APR1_MAGIC)
}

const MAGIC_LEN: usize = 6;

fn parse_md5_hash(hash: &str) -> Result<HashSetup> {
    let mut hs = parse::HashSlice::new(hash);
    if hs.take(MAGIC_LEN).unwrap_or("X") != APR1_MAGIC {
        return Err(Error::InvalidHashString);
    }
    let salt = if let Some(salt) = hs.take_until(b'$') {
        salt
    } else {
        return Err(Error::InvalidHashString);
    };
    Ok(HashSetup {
        salt: Some(salt),
        rounds: None,
    })
}

/// Hash a password with user-provided parameters.
///
/// If the `param` argument is a `&str`, it must be in the final hash
/// format. The salt is parsed out of that value.
/// If the salt is too long, it is truncated to maximum length. If it contains
/// an invalid character, an error is returned.
#[deprecated(since = "0.2.0", note = "don't use this algorithm for new passwords")]
pub fn hash_with<'a, IHS, B>(param: IHS, pass: B) -> Result<String>
where
    IHS: IntoHashSetup<'a>,
    B: AsRef<[u8]>,
{
    let hs = IHS::into_hash_setup(param, parse_md5_hash)?;
    if let Some(salt) = hs.salt {
        let salt = if salt.len() <= MAX_SALT_LEN {
            salt
        } else if let Some(truncated_salt) = parse::HashSlice::new(salt).take(MAX_SALT_LEN) {
            truncated_salt
        } else {
            return Err(Error::InvalidHashString);
        };
        do_md5_crypt(pass.as_ref(), salt, APR1_MAGIC)
    } else {
        let salt = random::gen_salt_str(MAX_SALT_LEN);
        do_md5_crypt(pass.as_ref(), &salt, APR1_MAGIC)
    }
}

/// Verify that the hash corresponds to a password.
pub fn verify<B: AsRef<[u8]>>(pass: B, hash: &str) -> bool {
    #[allow(deprecated)]
    consteq(hash, hash_with(hash, pass))
}

#[cfg(test)]
mod tests {
    use super::HashSetup;

    #[test]
    #[allow(deprecated)]
    fn custom() {
        assert_eq!(
            super::hash_with("$apr1$63JlJ2NH$smE0mnB5h3tDri0zkpWXt1", "password").unwrap(),
            "$apr1$63JlJ2NH$smE0mnB5h3tDri0zkpWXt1"
        );
        assert_eq!(
            super::hash_with(
                HashSetup {
                    salt: Some("63JlJ2NH"),
                    rounds: None
                },
                "password"
            )
            .unwrap(),
            "$apr1$63JlJ2NH$smE0mnB5h3tDri0zkpWXt1"
        );
    }
}

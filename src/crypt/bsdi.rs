//! Enhanced DES-based hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! This algorithm was developed by BSDi for BSD/OS as an extension of
//! the traditional Unix __crypt__(3). It supports longer passwords, larger
//! salt, and a variable number of rounds. Despite that, the algorithm
//! is considered weak and is not recommended for new passwords.
//!
//! # Example
//!
//! ```
//! use crypt3::{crypt::bsdi, HashSetup};
//!
//! assert_eq!(
//!     bsdi::hash_with(
//!         HashSetup::default().salt("K0Ay").rounds(7250),
//!         "password").unwrap(),
//!     "_Gl/.K0Ay.aosctsbJ1k");
//! ```
//!
//! # Parameters
//!
//! * __Password length__: unlimited.
//!
//! * __Salt length__: 4 characters (24 bits).
//!
//! * __Rounds__: 1 to 2<sup>24</sup>-1. Default is 7250.
//!
//! # Hash Format
//!
//! The format of the hash is __`_`__*`{rounds}{salt}{checksum}`*, where:
//!
//! * *`{rounds}`* is a 4-character Base64 encoding of the number of rounds.
//!
//! * *`{salt}`* is a 4-character Base64 encoding of the salt.
//!
//! * *`{checksum}`* is a 11-character Base64 encoding of the checksum.

use crate::{
    HashSetup, IntoHashSetup, consteq,
    encode::decode_val,
    error::{Error, Result},
    hash::{Hash, HashV},
    internal::des::bsdi_crypt,
    parse::{self, HashIterator},
    random,
};

const MIN_ROUNDS: u32 = 1;
const MAX_ROUNDS: u32 = (1 << 24) - 1;

// `_` + rounds + salt + checksum
pub(crate) const HASH_LENGTH: usize = 1 + 4 + 4 + 11;

/// Default number of rounds.
///
/// The value is aligned with the default used on NetBSD.
pub const DEFAULT_ROUNDS: u32 = 7250;
/// Salt length.
pub const SALT_LEN: usize = 4;
const ROUNDS_LEN: usize = 4;

/// Hash a password with a randomly generated salt and the default
/// number of rounds.
///
/// An error is returned if the system random number generator cannot
/// be opened.
#[deprecated(since = "0.2.0", note = "don't use this algorithm for new passwords")]
#[inline]
pub fn hash<B: AsRef<[u8]>>(pass: B) -> Result<Hash> {
    let saltstr = random::gen_salt_str(SALT_LEN);
    let hash = bsdi_crypt(pass.as_ref(), &saltstr, DEFAULT_ROUNDS)?;
    Ok(Hash::Bsdi(HashV(hash)))
}

fn parse_bsdi_hash(hash: &str) -> Result<HashSetup> {
    let mut hs = parse::HashSlice::new(hash);
    if hs.take(1).unwrap_or("X") != "_" {
        return Err(Error::InvalidHashString);
    }

    let rounds = hs
        .take(ROUNDS_LEN)
        .map(|rounds| decode_val(rounds, SALT_LEN))
        .ok_or(Error::InvalidHashString)??;
    let salt = hs.take(SALT_LEN).ok_or(Error::InvalidHashString)?;

    Ok(HashSetup {
        salt: Some(salt),
        rounds: Some(rounds),
    })
}

/// Hash a password with user-provided parameters.
///
/// If the `param` argument is a `&str`, it must be in the final hash
/// format. The number of rounds and the salt are parsed out of that value.
/// An error is returned if the salt is too short or contains an invalid
/// character. An out-of-range rounds value will also result in an error.
#[deprecated(since = "0.2.0", note = "don't use this algorithm for new passwords")]
pub fn hash_with<'a, IHS, B>(param: IHS, pass: B) -> Result<Hash>
where
    IHS: IntoHashSetup<'a>,
    B: AsRef<[u8]>,
{
    let hs = IHS::into_hash_setup(param, parse_bsdi_hash)?;
    let rounds = if let Some(r) = hs.rounds {
        if !(MIN_ROUNDS..=MAX_ROUNDS).contains(&r) {
            return Err(Error::InvalidRounds);
        }
        r
    } else {
        DEFAULT_ROUNDS
    };

    let hash = match hs.salt {
        Some(salt) => bsdi_crypt(pass.as_ref(), salt, rounds),
        None => {
            let saltstr = random::gen_salt_str(SALT_LEN);
            bsdi_crypt(pass.as_ref(), &saltstr, rounds)
        }
    }?;
    Ok(Hash::Bsdi(HashV(hash)))
}

/// Verify that the hash corresponds to a password.
#[inline]
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
            super::hash_with(
                HashSetup {
                    salt: Some("K0Ay"),
                    rounds: None
                },
                "password"
            )
            .unwrap(),
            "_Gl/.K0Ay.aosctsbJ1k"
        );
        assert_eq!(
            super::hash_with("_Gl/.K0Ay.aosctsbJ1k", "password").unwrap(),
            "_Gl/.K0Ay.aosctsbJ1k"
        );
    }

    #[test]
    #[allow(deprecated)]
    #[should_panic(expected = "value: InvalidRounds")]
    fn bad_rounds() {
        let _ = super::hash_with(
            HashSetup {
                salt: Some("K0Ay"),
                rounds: Some(0),
            },
            "password",
        )
        .unwrap();
    }
}

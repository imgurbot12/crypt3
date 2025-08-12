use std::ops::{Deref, RangeInclusive};
use std::str::FromStr;

use crate::crypt;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub(crate) struct HashV(pub(crate) String);

impl Deref for HashV {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Object oriented hash abstraction
#[allow(private_interfaces)]
#[derive(Clone, Debug)]
pub enum Hash {
    /// [`crypt::apr1`] hash value
    #[cfg(feature = "apr1")]
    Apr1(HashV),
    /// [`crypt::bcrypt`] hash value
    #[cfg(feature = "bcrypt")]
    Bcrypt(HashV),
    /// [`crypt::bsdi`] hash value
    #[cfg(feature = "bsdi")]
    Bsdi(HashV),
    /// [`crypt::md5`] hash value
    #[cfg(feature = "md5")]
    Md5(HashV),
    /// [`crypt::sha1`] hash value
    #[cfg(feature = "sha1")]
    Sha1(HashV),
    /// [`crypt::sha256`] hash value
    #[cfg(feature = "sha2")]
    Sha256(HashV),
    /// [`crypt::sha512`] hash value
    #[cfg(feature = "sha2")]
    Sha512(HashV),
    /// [`crypt::unix`] hash value
    #[cfg(feature = "unix")]
    Unix(HashV),
}

impl Hash {
    /// Hash a password with same mechansim and parameters as base hash.
    pub fn hash_with<B: AsRef<[u8]>>(&self, pass: B) -> Result<Self> {
        #[allow(deprecated)]
        match self {
            #[cfg(feature = "apr1")]
            Self::Apr1(hash) => crypt::apr1::hash_with(hash.0.as_str(), pass),
            #[cfg(feature = "bcrypt")]
            Self::Bcrypt(hash) => crypt::bcrypt::hash_with(hash.0.as_str(), pass),
            #[cfg(feature = "bsdi")]
            Self::Bsdi(hash) => crypt::bsdi::hash_with(hash.0.as_str(), pass),
            #[cfg(feature = "md5")]
            Self::Md5(hash) => crypt::md5::hash_with(hash.0.as_str(), pass),
            #[cfg(feature = "sha1")]
            Self::Sha1(hash) => crypt::sha1::hash_with(hash.0.as_str(), pass),
            #[cfg(feature = "sha2")]
            Self::Sha256(hash) => crypt::sha256::hash_with(hash.0.as_str(), pass),
            #[cfg(feature = "sha2")]
            Self::Sha512(hash) => crypt::sha512::hash_with(hash.0.as_str(), pass),
            #[cfg(feature = "unix")]
            Self::Unix(hash) => crypt::unix::hash_with(hash.0.as_str(), pass),
        }
    }

    /// Verify that the hash corresponds to a password.
    pub fn verify<B: AsRef<[u8]>>(&self, pass: B) -> bool {
        match self {
            #[cfg(feature = "apr1")]
            Self::Apr1(hash) => crypt::apr1::verify(pass, &hash.0),
            #[cfg(feature = "bcrypt")]
            Self::Bcrypt(hash) => crypt::bcrypt::verify(pass, &hash.0),
            #[cfg(feature = "bsdi")]
            Self::Bsdi(hash) => crypt::bsdi::verify(pass, &hash.0),
            #[cfg(feature = "md5")]
            Self::Md5(hash) => crypt::md5::verify(pass, &hash.0),
            #[cfg(feature = "sha1")]
            Self::Sha1(hash) => crypt::sha1::verify(pass, &hash.0),
            #[cfg(feature = "sha2")]
            Self::Sha256(hash) => crypt::sha256::verify(pass, &hash.0),
            #[cfg(feature = "sha2")]
            Self::Sha512(hash) => crypt::sha512::verify(pass, &hash.0),
            #[cfg(feature = "unix")]
            Self::Unix(hash) => crypt::unix::verify(pass, &hash.0),
        }
    }
}

impl Hash {
    /// Return ref to inner hash value string.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self
    }
}

impl Into<String> for Hash {
    fn into(self) -> String {
        match self {
            #[cfg(feature = "apr1")]
            Self::Apr1(hash) => hash.0,
            #[cfg(feature = "bcrypt")]
            Self::Bcrypt(hash) => hash.0,
            #[cfg(feature = "bsdi")]
            Self::Bsdi(hash) => hash.0,
            #[cfg(feature = "md5")]
            Self::Md5(hash) => hash.0,
            #[cfg(feature = "sha1")]
            Self::Sha1(hash) => hash.0,
            #[cfg(feature = "sha2")]
            Self::Sha256(hash) => hash.0,
            #[cfg(feature = "sha2")]
            Self::Sha512(hash) => hash.0,
            #[cfg(feature = "unix")]
            Self::Unix(hash) => hash.0,
        }
    }
}

impl Deref for Hash {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            #[cfg(feature = "apr1")]
            Self::Apr1(hash) => &hash.0,
            #[cfg(feature = "bcrypt")]
            Self::Bcrypt(hash) => &hash.0,
            #[cfg(feature = "bsdi")]
            Self::Bsdi(hash) => &hash.0,
            #[cfg(feature = "md5")]
            Self::Md5(hash) => &hash.0,
            #[cfg(feature = "sha1")]
            Self::Sha1(hash) => &hash.0,
            #[cfg(feature = "sha2")]
            Self::Sha256(hash) => &hash.0,
            #[cfg(feature = "sha2")]
            Self::Sha512(hash) => &hash.0,
            #[cfg(feature = "unix")]
            Self::Unix(hash) => &hash.0,
        }
    }
}

impl PartialEq<Hash> for Hash {
    #[inline]
    fn eq(&self, other: &Hash) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<Hash> for String {
    #[inline]
    fn eq(&self, other: &Hash) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<String> for Hash {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<Hash> for &str {
    #[inline]
    fn eq(&self, other: &Hash) -> bool {
        self == &other.as_str()
    }
}

impl PartialEq<&str> for Hash {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        &self.as_str() == other
    }
}

#[inline]
fn gatel(s: &str, size: usize) -> Result<HashV> {
    (s.len() == size)
        .then(|| HashV(s.to_owned()))
        .ok_or(Error::InsufficientLength)
}

#[inline]
fn gater(s: &str, range: RangeInclusive<usize>) -> Result<HashV> {
    range
        .contains(&s.len())
        .then(|| HashV(s.to_owned()))
        .ok_or(Error::InsufficientLength)
}

impl TryFrom<&str> for Hash {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        use crate::parse::HashIterator;

        let mut hs = crate::parse::HashSlice::new(value);
        match hs.take(1).unwrap_or("X") {
            #[cfg(feature = "bsdi")]
            "_" => Ok(Self::Bsdi(gatel(value, crypt::bsdi::HASH_LENGTH)?)),
            "$" => match hs.take_until(b'$').unwrap_or("X") {
                #[cfg(feature = "md5")]
                "1" => Ok(Self::Md5(gater(value, crypt::md5::HASH_LENGTH)?)),
                #[cfg(feature = "apr1")]
                "apr1" => Ok(Self::Apr1(gater(value, crypt::apr1::HASH_LENGTH)?)),
                #[cfg(feature = "bcrypt")]
                "2a" | "2b" | "2y" => Ok(Self::Bcrypt(gatel(value, crypt::bcrypt::HASH_LENGTH)?)),
                #[cfg(feature = "sha1")]
                "sha1" => Ok(Self::Sha1(gater(value, crypt::sha1::HASH_LENGTH)?)),
                #[cfg(feature = "sha2")]
                "5" => Ok(Self::Sha256(gater(value, crypt::sha256::HASH_LENGTH)?)),
                #[cfg(feature = "sha2")]
                "6" => Ok(Self::Sha512(gater(value, crypt::sha512::HASH_LENGTH)?)),
                _ => Err(Error::InvalidHashString),
            },
            #[cfg(feature = "unix")]
            _ if value.len() == crypt::unix::HASH_LENGTH => Ok(Self::Unix(HashV(value.to_owned()))),
            _ => Err(Error::InvalidHashString),
        }
    }
}

impl FromStr for Hash {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        s.try_into()
    }
}

#[cfg(test)]
mod tests {

    use super::Hash;

    #[test]
    fn fromstr() {
        #[cfg(feature = "apr1")]
        assert!(matches!(
            Hash::try_from("$apr1$63JlJ2NH$smE0mnB5h3tDri0zkpWXt1").unwrap(),
            Hash::Apr1(_)
        ));
        #[cfg(feature = "bcrypt")]
        assert!(matches!(
            Hash::try_from("$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe").unwrap(),
            Hash::Bcrypt(_)
        ));
        #[cfg(feature = "bcrypt")]
        assert!(matches!(
            Hash::try_from("_Gl/.K0Ay.aosctsbJ1k").unwrap(),
            Hash::Bsdi(_)
        ));
        #[cfg(feature = "md5")]
        assert!(matches!(
            Hash::try_from("$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0").unwrap(),
            Hash::Md5(_)
        ));
        #[cfg(feature = "sha1")]
        assert!(matches!(
            Hash::try_from("$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a").unwrap(),
            Hash::Sha1(_)
        ));
        #[cfg(feature = "sha2")]
        assert!(matches!(
            Hash::try_from(
                "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1"
            )
            .unwrap(),
            Hash::Sha256(_)
        ));
        #[cfg(feature = "sha2")]
        assert!(matches!(
            Hash::try_from(
                "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13\
		            uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1"
            )
            .unwrap(),
            Hash::Sha512(_)
        ));
        #[cfg(feature = "unix")]
        assert!(matches!(
            Hash::try_from("aZGJuE6EXrjEE").unwrap(),
            Hash::Unix(_)
        ));
    }
}

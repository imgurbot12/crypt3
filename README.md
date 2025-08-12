# crypt3_rs

Unix crypt(3) reimplemented in pure rust.

See the [documentation](https://docs.rs/crypt3_rs/0.1.0/crypt3_rs/) for API reference.

## Examples

```rust
use crypt3_rs::crypt::bcrypt;

// Hash a password with default parameters.
let h_new = bcrypt::hash("password").unwrap();

// Verify a password against an existing hash.
let h = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
assert!(bcrypt::verify("password", h));
```

## Summary

The following algorithms are currently implemented (in alphabetical order):

* apr1_crypt
* bcrypt
* bsdi_crypt
* md5_crypt
* sha1_crypt
* sha256_crypt
* sha512_crypt
* unix_crypt

Each algorithm resides in its eponymous module, and provides the following
interface:

* `verify()`: verify a password against a hash.
* `hash()`: hash a password with default algorithm-spacific parameters.
* `hash_with()`: hash a password with customized parameters.

There is also a convenience module `unix` which provides the functions
`unix::crypt`, a __crypt__(3) work-alike, and `unix::verify`.

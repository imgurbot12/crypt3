use rand::{distr::StandardUniform, random, Rng};

use super::encode::bcrypt_hash64_encode;

pub fn gen_salt_str(chars: usize) -> String {
    let bytes = chars.div_ceil(4) * 3;
    let rv = rand::rng()
        .sample_iter(&StandardUniform)
        .take(bytes)
        .collect::<Vec<u8>>();

    let mut sstr = bcrypt_hash64_encode(&rv);
    while sstr.len() > chars {
        sstr.pop();
    }
    sstr
}

#[inline]
pub fn gen_salt_bytes(bytes: &mut [u8]) {
    rand::rng().fill(bytes);
}

#[inline]
pub fn vary_rounds(ceil: u32) -> u32 {
    ceil - (random::<u32>() % (ceil / 4))
}

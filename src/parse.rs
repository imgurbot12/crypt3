use std::str;

/// A trait for traversing a hash string.
///
/// Hash strings have internal structure: they consist of a concatenation
/// of a number of substrings. This trait enables extracting references to
/// those substrings with the necessary semantics.
pub trait HashIterator {
    /// The substring that is returned by methods.
    type Elem;

    /// Extract a fixed-size substring.
    ///
    /// There must be <i>at least</i> `n` ASCII characters remaining in the
    /// string. If there are less, `None` is returned. If called with a non-zero
    /// `n`, this method drains the string: if there are exactly `n` characters
    /// remaining, subsequent calls will return `None`.
    ///
    /// Calling `take` with `n` set to zero returns an empty string if the main
    /// string is not drained.
    fn take(&mut self, n: usize) -> Option<Self::Elem>;

    /// Extract a substring delimited by a byte.
    ///
    /// Return a substring from the current position to the next occurrence of the
    /// ASCII delimiter `ac` or the end of the string. If the delimiter is found,
    /// advance the position one byte after it. Drains the string.
    fn take_until(&mut self, ac: u8) -> Option<Self::Elem>;

    /// Returns `true` if the string is not drained.
    #[allow(dead_code)]
    fn at_end(&mut self) -> bool;
}

pub struct HashSlice<'a> {
    bp: &'a [u8],
    len: usize,
    pos: usize,
}

impl<'a> HashSlice<'a> {
    pub fn new(hash: &'a str) -> HashSlice<'a> {
        HashSlice {
            bp: hash.as_bytes(),
            len: hash.len(),
            pos: 0,
        }
    }
}

impl<'a> HashIterator for HashSlice<'a> {
    type Elem = &'a str;

    fn take(&mut self, n: usize) -> Option<Self::Elem> {
        if self.pos > self.len {
            return None;
        }
        let sp = self.pos;
        if sp + n > self.len {
            self.pos = self.len + 1;
            None
        } else {
            let endp = self.pos + n;
            self.pos = endp + if endp == self.len { 1 } else { 0 };
            str::from_utf8(&self.bp[sp..endp]).ok()
        }
    }

    fn take_until(&mut self, ac: u8) -> Option<Self::Elem> {
        if self.pos > self.len {
            return None;
        }
        let mut sp = self.pos;
        while sp < self.len {
            if self.bp[sp] == ac {
                break;
            }
            sp += 1;
        }
        let oldp = self.pos;
        self.pos = sp + 1;
        str::from_utf8(&self.bp[oldp..sp]).ok()
    }

    fn at_end(&mut self) -> bool {
        self.take(0).unwrap_or("X") == "X"
    }
}

#[cfg(test)]
mod tests {
    use super::{HashIterator, HashSlice};

    #[test]
    fn drain_string() {
        let mut hs = HashSlice::new("$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe");
        assert_eq!(hs.take_until(b'$').unwrap(), "");
        assert_eq!(hs.take_until(b'$').unwrap(), "2y");
        assert_eq!(hs.take_until(b'$').unwrap(), "05");
        assert_eq!(hs.take(22).unwrap(), "bvIG6Nmid91Mu9RcmmWZfO");
        let mut hs1 = HashSlice {
            bp: hs.bp,
            pos: hs.pos,
            len: hs.len,
        };
        assert_eq!(
            hs.take_until(b'$').unwrap(),
            "5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe"
        );
        assert_eq!(hs.at_end(), true);
        assert_eq!(hs1.take(31).unwrap(), "5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe");
        assert_eq!(hs1.at_end(), true);
    }

    #[test]
    fn empty_string() {
        let mut hs = HashSlice::new("");
        assert_eq!(hs.take_until(b'$').unwrap(), "");
        assert_eq!(hs.at_end(), true);
        let mut hs = HashSlice::new("");
        assert_eq!(hs.at_end(), false);
    }

    #[test]
    fn empty_elements() {
        let mut hs = HashSlice::new("$");
        assert_eq!(hs.take_until(b'$').unwrap(), "");
        assert_eq!(hs.take_until(b'$').unwrap(), "");
        assert_eq!(hs.at_end(), true);
    }

    #[test]
    fn combined_take() {
        let mut hs = HashSlice::new("$");
        let _ = hs.take_until(b'$').unwrap();
        assert_eq!(hs.take_until(b'$').unwrap(), "");
        assert_eq!(hs.at_end(), true);
    }
}

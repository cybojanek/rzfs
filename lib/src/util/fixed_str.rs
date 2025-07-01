// SPDX-License-Identifier: GPL-2.0 OR MIT
use core::fmt;

/// String of a fixed capacity, and variable length.
#[derive(Debug)]
pub struct Fstr<const N: usize> {
    bytes: [u8; N],
    size: usize,
    trimmed: bool,
}

impl<const N: usize> fmt::Display for Fstr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let suffix = if self.trimmed { ".." } else { "" };
        match self.as_str() {
            Some(s) => write!(f, "{s}{suffix}"),
            None => write!(f, "{:?}{suffix}", self.bytes),
        }
    }
}

impl<const N: usize> Fstr<N> {
    /// Gets string bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[0..self.size]
    }

    /** Gets bytes decoded as a utf8 string.
     *
     * Returns [None] if byte string failed to decode as utf8.
     */
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }

    /// Gets the capacity of the string in bytes.
    pub fn capacity(&self) -> usize {
        N
    }

    /// Returns [true] if the string is empty [""].
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns [true] if the fixed string is trimmed.
    pub fn is_trimmed(&self) -> bool {
        self.trimmed
    }

    /// Gets the length of the string in bytes.
    pub fn len(&self) -> usize {
        self.size
    }
}

impl<const N: usize> From<&[u8]> for Fstr<N> {
    fn from(bytes: &[u8]) -> Self {
        let size = bytes.len().min(N);

        let mut f = Fstr {
            bytes: [0; N],
            size,
            trimmed: size < bytes.len(),
        };

        f.bytes[0..size].copy_from_slice(&bytes[0..size]);

        f
    }
}

impl<const N: usize> From<&str> for Fstr<N> {
    /** Gets the [`Fstr::<N>`] from the string.
     *
     * If the byte length of `s` is larger than `N`, then the string bytes will
     * try to be trimmed to a valid utf8 string.
     */
    fn from(s: &str) -> Self {
        // Get bytes and length.
        let bytes = s.as_bytes();
        let mut size = bytes.len().min(N);

        if N > 0 && bytes.len() > N {
            // A utf8 string can use up to 4 bytes per code point, so try to
            // find a valid encoding by trimming up to 3 bytes, but leaving
            // at least one byte.
            for truncate in 0..size.min(4) {
                let tsize = size - truncate;
                if core::str::from_utf8(&bytes[0..tsize]).is_ok() {
                    size = tsize;
                    break;
                }
            }
            // Otherwise...just keep going.
        }

        let mut f = Fstr {
            bytes: [0; N],
            size,
            trimmed: size < bytes.len(),
        };

        f.bytes[0..size].copy_from_slice(&bytes[0..size]);

        f
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {

    use crate::util::Fstr;

    macro_rules! check_fstr_display {
        ($s: expr, $f:expr, $a: expr) => {
            assert_eq!($f.as_str().unwrap(), $a);

            if $s.as_bytes().len() > $f.capacity() {
                assert_eq!(format!("{}", $f), format!("{}..", $a));
                assert!($f.is_trimmed());
            } else {
                assert_eq!(format!("{}", $f), format!("{}", $a));
                assert!(!$f.is_trimmed());
            }
        };
    }

    #[test]
    fn bytes() {
        let abcd = "a÷⟰🂡";
        let bytes = abcd.as_bytes();

        // Loop over all byte lengths of the string.
        for size in 0..bytes.len() {
            let bytes = &bytes[0..size];
            let is_ok = core::str::from_utf8(bytes).is_ok();

            let f = Fstr::<10>::from(bytes);
            assert!(!f.is_trimmed());

            // Bytes must match.
            assert_eq!(f.as_bytes(), bytes);

            // String will only be Some if it decodes successfully.
            assert_eq!(f.as_str().is_some(), is_ok);
        }
    }

    #[test]
    fn ascii() {
        let full_string = "0123456789abcdef";
        let max_string = "01234567";

        for size in 0..full_string.len() {
            let sub_bytes = &full_string.as_bytes()[0..size];
            let sub_string = core::str::from_utf8(sub_bytes).unwrap();

            let f = Fstr::<8>::from(sub_string);

            // Capacity is unchanged.
            assert_eq!(f.capacity(), 8);

            if size > f.capacity() {
                check_fstr_display!(sub_string, f, max_string);
            } else {
                check_fstr_display!(sub_string, f, sub_string);
            }
        }
    }

    #[test]
    fn unicode() {
        // Full string with 1 + 2 + 3 + 4 utf8 bytes per character.
        let a = "a";
        let ab = "a÷";
        let abc = "a÷⟰";
        let abcd = "a÷⟰🂡";

        let all = [&a, &ab, &abc, &abcd];

        assert_eq!(a.as_bytes().len(), 1);
        assert_eq!(ab.as_bytes().len(), 3);
        assert_eq!(abc.as_bytes().len(), 6);
        assert_eq!(abcd.as_bytes().len(), 10);

        // Empty.
        for s in all {
            let f = Fstr::<0>::from(*s);
            check_fstr_display!(s, f, "");
        }

        // a
        for s in all {
            let f = Fstr::<1>::from(*s);
            check_fstr_display!(s, f, a);

            let f = Fstr::<2>::from(*s);
            check_fstr_display!(s, f, a);
        }

        // ab
        for s in &all[1..] {
            let f = Fstr::<3>::from(**s);
            check_fstr_display!(s, f, ab);

            let f = Fstr::<4>::from(**s);
            check_fstr_display!(s, f, ab);

            let f = Fstr::<5>::from(**s);
            check_fstr_display!(s, f, ab);
        }

        // abc
        for s in &all[2..] {
            let f = Fstr::<6>::from(**s);
            check_fstr_display!(s, f, abc);

            let f = Fstr::<7>::from(**s);
            check_fstr_display!(s, f, abc);

            let f = Fstr::<8>::from(**s);
            check_fstr_display!(s, f, abc);

            let f = Fstr::<9>::from(**s);
            check_fstr_display!(s, f, abc);
        }

        // abcd
        let f = Fstr::<10>::from(abcd);
        check_fstr_display!(abcd, f, abcd);

        let f = Fstr::<11>::from(abcd);
        check_fstr_display!(abcd, f, abcd);
    }

    #[test]
    fn zero() {
        let f = Fstr::<0>::from("hello");
        check_fstr_display!("hello", f, "");

        let f = Fstr::<0>::from("");
        check_fstr_display!("", f, "");
    }
}

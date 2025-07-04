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
        // If the bytes are not a valid utf8 sequence, then print them as
        // a byte array.
        match self.as_str() {
            Some(s) => write!(f, "{s}"),
            None => write!(f, "{:?}", &self.bytes[0..self.size]),
        }
    }
}

impl<const N: usize> Fstr<N> {
    /// Creates a new fixed size string. Caller must clamp length.
    fn new(bytes: &[u8], trimmed: bool) -> Fstr<N> {
        let size = bytes.len();

        let mut f = Fstr {
            bytes: [0; N],
            size,
            trimmed,
        };

        f.bytes[0..size].copy_from_slice(bytes);

        f
    }

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

    /// Returns [true] if the fixed string was trimmed in [`Fstr<N>::from`].
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
        // Trim input to at most N bytes.
        let size = bytes.len().min(N);
        let trimmed = size < bytes.len();

        Fstr::<N>::new(&bytes[0..size], trimmed)
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
            // Otherwise...just use the bytes as they are.
        }

        let trimmed = size < bytes.len();

        Fstr::<N>::new(&bytes[0..size], trimmed)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {

    use crate::util::Fstr;

    macro_rules! check_fstr_display {
        ($source: expr, $fixed:expr, $sub_string: expr) => {
            assert_eq!($fixed.as_str().unwrap(), $sub_string);

            assert_eq!(format!("{}", $fixed), format!("{}", $sub_string));
            assert_eq!(
                $fixed.is_trimmed(),
                $source.as_bytes().len() > $fixed.capacity()
            );
        };
    }

    #[test]
    fn from_bytes() {
        let abcd = "a÷⟰🂡";
        let bytes = abcd.as_bytes();
        assert_eq!(bytes.len(), 10);

        // Loop over all byte lengths of the string.
        for size in 0..bytes.len() {
            let bytes = &bytes[0..size];

            // Depending on where the bytes were truncated, the bytes may or
            // may not decode as a valid utf8 sequence.
            let is_ok = core::str::from_utf8(bytes).is_ok();

            let f = Fstr::<10>::from(bytes);
            assert_eq!(f.capacity(), 10);

            // The string will not be trimmed, because there is enough space,
            // and from bytes does not check for utf8 validity.
            assert_eq!(f.is_trimmed(), false);

            // Bytes must match.
            assert_eq!(f.as_bytes(), bytes);
            assert_eq!(f.len(), bytes.len());
            assert_eq!(f.is_empty(), bytes.len() == 0);

            if is_ok {
                // String will only be Some if it decodes successfully.
                let s = core::str::from_utf8(bytes).unwrap();
                assert_eq!(f.as_str().unwrap(), s);
                assert_eq!(format!("{}", f), format!("{}", s));
            } else {
                // Else it will be None, and printed as bytes.
                assert!(f.as_str().is_none());
                assert_eq!(format!("{}", f), format!("{:?}", bytes));
            }
        }

        // Loop over all byte lengths of the string.
        for size in 0..bytes.len() {
            let bytes = &bytes[0..size];

            // Depending on where the bytes were truncated, the bytes may or
            // may not decode as a valid utf8 sequence.
            let exp_bytes = if bytes.len() > 5 { &bytes[0..5] } else { bytes };
            let is_ok = core::str::from_utf8(exp_bytes).is_ok();

            let f = Fstr::<5>::from(bytes);
            assert_eq!(f.capacity(), 5);

            // The string will may be trimmed.
            assert_eq!(f.is_trimmed(), exp_bytes.len() < bytes.len());

            // Bytes must match.
            assert_eq!(f.as_bytes(), exp_bytes);
            assert_eq!(f.len(), exp_bytes.len());
            assert_eq!(f.is_empty(), exp_bytes.len() == 0);

            if is_ok {
                // String will only be Some if it decodes successfully.
                let s = core::str::from_utf8(exp_bytes).unwrap();
                assert_eq!(f.as_str().unwrap(), s);
                assert_eq!(format!("{}", f), format!("{}", s));
            } else {
                // Else it will be None, and printed as bytes.
                assert!(f.as_str().is_none());
                assert_eq!(format!("{}", f), format!("{:?}", exp_bytes));
            }
        }
    }

    #[test]
    fn from_ascii() {
        let full_string = "0123456789abcdef";
        let max_string = "01234567";

        // Loop over all byte lengths of the string.
        for size in 0..full_string.len() {
            let sub_bytes = &full_string.as_bytes()[0..size];
            let sub_string = core::str::from_utf8(sub_bytes).unwrap();

            let f = Fstr::<8>::from(sub_string);

            // Capacity is unchanged.
            assert_eq!(f.capacity(), 8);

            let expected_string = if size > f.capacity() {
                max_string
            } else {
                sub_string
            };

            check_fstr_display!(sub_string, f, expected_string);
        }
    }

    #[test]
    fn from_unicode() {
        // Full string with 1 + 2 + 3 + 4 utf8 bytes per character.
        let a = "a";
        let ab = "a÷";
        let abc = "a÷⟰";
        let abcd = "a÷⟰🂡";

        assert_eq!(a.as_bytes().len(), 1);
        assert_eq!(ab.as_bytes().len(), 3);
        assert_eq!(abc.as_bytes().len(), 6);
        assert_eq!(abcd.as_bytes().len(), 10);

        // Empty.
        for s in [&a, &ab, &abc, &abcd] {
            let f = Fstr::<0>::from(*s);
            check_fstr_display!(s, f, "");
        }

        // Given a capcity of 1 or 2, the example inputs will alway be
        // trimmed to just a, because the valid utf8 lengths are 1, 3, 6, 10.
        for s in [&a, &ab, &abc, &abcd] {
            let f = Fstr::<1>::from(*s);
            check_fstr_display!(s, f, a);

            let f = Fstr::<2>::from(*s);
            check_fstr_display!(s, f, a);
        }

        // Given a capcity of 3, 4, 5, the example inputs will alway be
        // trimmed to just ab, because the valid utf8 lengths are 3, 6, 10.
        for s in [&ab, &abc, &abcd] {
            let f = Fstr::<3>::from(*s);
            check_fstr_display!(s, f, ab);

            let f = Fstr::<4>::from(*s);
            check_fstr_display!(s, f, ab);

            let f = Fstr::<5>::from(*s);
            check_fstr_display!(s, f, ab);
        }

        // Given a capcity of 6, 7, 8, 9, the example inputs will alway be
        // trimmed to just abc, because the valid utf8 lengths are 6, 10.
        for s in [&abc, &abcd] {
            let f = Fstr::<6>::from(*s);
            check_fstr_display!(s, f, abc);

            let f = Fstr::<7>::from(*s);
            check_fstr_display!(s, f, abc);

            let f = Fstr::<8>::from(*s);
            check_fstr_display!(s, f, abc);

            let f = Fstr::<9>::from(*s);
            check_fstr_display!(s, f, abc);
        }

        // Given a capcity of 10 or more, the inputs are not trimmed.
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

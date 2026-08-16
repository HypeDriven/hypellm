//! Base64 and Base64url (RFC 4648).
//!
//! Used for OIDC PKCE verifier/challenge and `state`, session cookie values,
//! API key material, and JWT segment decoding at the verifier boundary.
//!
//! Decoding is strict: no whitespace, no alternate alphabets, no non-canonical
//! trailing bits. Lenient base64 decoders are a recurring source of signature
//! bypass and cache-poisoning bugs, so the router refuses anything ambiguous.

/// Alphabet selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// `A-Za-z0-9+/`
    Standard,
    /// `A-Za-z0-9-_` (RFC 4648 section 5)
    UrlSafe,
}

/// Padding policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    /// `=` padding required to a multiple of 4.
    Required,
    /// `=` padding must be absent.
    Forbidden,
}

/// Error returned by [`decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// A character outside the selected alphabet appeared.
    InvalidCharacter,
    /// The encoded length is impossible (for example a group of one symbol).
    InvalidLength,
    /// Padding was present when forbidden, absent when required, or misplaced.
    InvalidPadding,
    /// The final symbol carried non-zero bits that decode to nothing.
    NonCanonical,
    /// Decoding would exceed the caller-supplied output bound.
    TooLong,
}

impl core::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::InvalidCharacter => "base64 input contains an out-of-alphabet character",
            Self::InvalidLength => "base64 input length is invalid",
            Self::InvalidPadding => "base64 padding is invalid",
            Self::NonCanonical => "base64 input has non-canonical trailing bits",
            Self::TooLong => "base64 decoded output exceeds the permitted bound",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Base64Error {}

/// The RFC 4648 symbol for a six-bit value — the exact inverse of
/// [`symbol_value`], expressed arithmetically rather than as a table lookup so
/// that it is total: the mask bounds the input to `0..=63`, each arm bounds its
/// own addition, and no index can be out of range. The `alphabets_match_rfc4648`
/// test pins it against the published alphabets.
fn symbol_char(v: u8, a: Alphabet) -> char {
    match v & 0x3f {
        n @ 0..=25 => char::from(b'A' + n),
        n @ 26..=51 => char::from(b'a' + n - 26),
        n @ 52..=61 => char::from(b'0' + n - 52),
        62 => match a {
            Alphabet::Standard => '+',
            Alphabet::UrlSafe => '-',
        },
        _ => match a {
            Alphabet::Standard => '/',
            Alphabet::UrlSafe => '_',
        },
    }
}

const fn symbol_value(c: u8, a: Alphabet) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => match a {
            Alphabet::Standard => Some(62),
            Alphabet::UrlSafe => None,
        },
        b'/' => match a {
            Alphabet::Standard => Some(63),
            Alphabet::UrlSafe => None,
        },
        b'-' => match a {
            Alphabet::UrlSafe => Some(62),
            Alphabet::Standard => None,
        },
        b'_' => match a {
            Alphabet::UrlSafe => Some(63),
            Alphabet::Standard => None,
        },
        _ => None,
    }
}

/// Encode `data`.
#[must_use]
pub fn encode(data: &[u8], alphabet: Alphabet, padding: Padding) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        // `chunks(3)` never yields an empty slice; the absent bytes of a short
        // final group contribute zero bits, as RFC 4648 section 4 requires.
        let (b0, b1, b2) = match *chunk {
            [b0] => (b0, 0, 0),
            [b0, b1] => (b0, b1, 0),
            [b0, b1, b2, ..] => (b0, b1, b2),
            [] => continue,
        };

        out.push(symbol_char(b0 >> 2, alphabet));
        out.push(symbol_char(((b0 & 0x03) << 4) | (b1 >> 4), alphabet));
        if chunk.len() > 1 {
            out.push(symbol_char(((b1 & 0x0f) << 2) | (b2 >> 6), alphabet));
        } else if padding == Padding::Required {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(symbol_char(b2, alphabet));
        } else if padding == Padding::Required {
            out.push('=');
        }
    }
    out
}

/// Encode with the URL-safe alphabet and no padding — the OIDC/JWT convention.
#[must_use]
pub fn encode_url_nopad(data: &[u8]) -> String {
    encode(data, Alphabet::UrlSafe, Padding::Forbidden)
}

/// Encode with the standard alphabet and padding.
#[must_use]
pub fn encode_std(data: &[u8]) -> String {
    encode(data, Alphabet::Standard, Padding::Required)
}

/// Decode `input`, rejecting anything non-canonical.
///
/// `max_output` bounds the decoded size before allocation (specification 3.2:
/// explicit maxima before allocation).
pub fn decode(
    input: &[u8],
    alphabet: Alphabet,
    padding: Padding,
    max_output: usize,
) -> Result<Vec<u8>, Base64Error> {
    let body = match padding {
        Padding::Forbidden => {
            if input.contains(&b'=') {
                return Err(Base64Error::InvalidPadding);
            }
            input
        }
        Padding::Required => {
            if input.len() % 4 != 0 {
                return Err(Base64Error::InvalidPadding);
            }
            let pad = input.iter().rev().take_while(|c| **c == b'=').count();
            if pad > 2 {
                return Err(Base64Error::InvalidPadding);
            }
            // `pad` counts trailing bytes of `input`, so it never exceeds its
            // length and the split point is in range.
            let (body, _) = input.split_at(input.len() - pad);
            if body.contains(&b'=') {
                return Err(Base64Error::InvalidPadding);
            }
            body
        }
    };

    if body.len() % 4 == 1 {
        return Err(Base64Error::InvalidLength);
    }

    let mut chunks = body.chunks_exact(4);
    // Counted before iteration: `ChunksExact::len` shrinks as it is consumed.
    // Three output bytes per complete group, plus the partial tail.
    let rem = chunks.remainder();
    let out_len = chunks.len() * 3
        + match rem.len() {
            2 => 1,
            3 => 2,
            _ => 0,
        };
    if out_len > max_output {
        return Err(Base64Error::TooLong);
    }

    let mut out = Vec::with_capacity(out_len);
    for chunk in chunks.by_ref() {
        let [c0, c1, c2, c3] = chunk else {
            // Unreachable: `chunks_exact(4)` yields four-element slices.
            return Err(Base64Error::InvalidLength);
        };
        let v0 = symbol_value(*c0, alphabet).ok_or(Base64Error::InvalidCharacter)?;
        let v1 = symbol_value(*c1, alphabet).ok_or(Base64Error::InvalidCharacter)?;
        let v2 = symbol_value(*c2, alphabet).ok_or(Base64Error::InvalidCharacter)?;
        let v3 = symbol_value(*c3, alphabet).ok_or(Base64Error::InvalidCharacter)?;
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
        out.push((v2 << 6) | v3);
    }

    match *rem {
        [] => {}
        [c0, c1] => {
            let v0 = symbol_value(c0, alphabet).ok_or(Base64Error::InvalidCharacter)?;
            let v1 = symbol_value(c1, alphabet).ok_or(Base64Error::InvalidCharacter)?;
            if v1 & 0x0f != 0 {
                return Err(Base64Error::NonCanonical);
            }
            out.push((v0 << 2) | (v1 >> 4));
        }
        [c0, c1, c2] => {
            let v0 = symbol_value(c0, alphabet).ok_or(Base64Error::InvalidCharacter)?;
            let v1 = symbol_value(c1, alphabet).ok_or(Base64Error::InvalidCharacter)?;
            let v2 = symbol_value(c2, alphabet).ok_or(Base64Error::InvalidCharacter)?;
            if v2 & 0x03 != 0 {
                return Err(Base64Error::NonCanonical);
            }
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
        }
        _ => return Err(Base64Error::InvalidLength),
    }

    Ok(out)
}

/// Decode URL-safe, unpadded input — the OIDC/JWT convention.
pub fn decode_url_nopad(input: &[u8], max_output: usize) -> Result<Vec<u8>, Base64Error> {
    decode(input, Alphabet::UrlSafe, Padding::Forbidden, max_output)
}

/// Decode standard, padded input.
pub fn decode_std(input: &[u8], max_output: usize) -> Result<Vec<u8>, Base64Error> {
    decode(input, Alphabet::Standard, Padding::Required, max_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The published RFC 4648 alphabets, kept here as the reference the
    // arithmetic `symbol_char` must reproduce symbol for symbol.
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    #[test]
    fn alphabets_match_rfc4648() {
        for (v, (s, u)) in STD.iter().zip(URL.iter()).enumerate() {
            let v = u8::try_from(v).expect("index below 64");
            assert_eq!(symbol_char(v, Alphabet::Standard), char::from(*s), "std {v}");
            assert_eq!(symbol_char(v, Alphabet::UrlSafe), char::from(*u), "url {v}");
            // And the encoder/decoder agree on every symbol.
            assert_eq!(symbol_value(*s, Alphabet::Standard), Some(v));
            assert_eq!(symbol_value(*u, Alphabet::UrlSafe), Some(v));
        }
    }

    #[test]
    fn rfc4648_vectors() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode_std(plain), encoded, "encode {plain:?}");
            assert_eq!(decode_std(encoded.as_bytes(), 64).unwrap(), plain);
        }
    }

    #[test]
    fn url_alphabet_differs() {
        let data = [0xfbu8, 0xff, 0xbe];
        let std = encode(&data, Alphabet::Standard, Padding::Required);
        let url = encode(&data, Alphabet::UrlSafe, Padding::Forbidden);
        assert!(std.contains('+') || std.contains('/'));
        assert!(!url.contains('+') && !url.contains('/') && !url.contains('='));
        assert_eq!(decode_url_nopad(url.as_bytes(), 8).unwrap(), data);
    }

    #[test]
    fn roundtrip_all_lengths() {
        for len in 0..200usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
            let e = encode_url_nopad(&data);
            assert_eq!(decode_url_nopad(e.as_bytes(), 256).unwrap(), data, "len {len}");
            let e2 = encode_std(&data);
            assert_eq!(decode_std(e2.as_bytes(), 256).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn rejects_cross_alphabet() {
        assert_eq!(
            decode(b"Zm-x", Alphabet::Standard, Padding::Forbidden, 8),
            Err(Base64Error::InvalidCharacter)
        );
        assert_eq!(
            decode(b"Zm+x", Alphabet::UrlSafe, Padding::Forbidden, 8),
            Err(Base64Error::InvalidCharacter)
        );
    }

    #[test]
    fn rejects_whitespace_and_control() {
        // A 9-byte input is rejected on length before the alphabet is consulted;
        // either rejection is acceptable, silent acceptance is not.
        assert!(decode_std(b"Zm9v\nYmFy", 16).is_err());
        assert!(decode_url_nopad(b"Zm9v YmFy", 16).is_err());
        // An 8-byte input reaches the alphabet check, which must reject the
        // embedded control and space characters rather than skipping them.
        assert_eq!(
            decode_url_nopad(b"Zm9\nYmFy", 16),
            Err(Base64Error::InvalidCharacter)
        );
        assert_eq!(
            decode_url_nopad(b"Zm9 YmFy", 16),
            Err(Base64Error::InvalidCharacter)
        );
        assert_eq!(
            decode_std(b"Zm9\tYmFy", 16),
            Err(Base64Error::InvalidCharacter)
        );
    }

    #[test]
    fn rejects_non_canonical_tail() {
        // "Zh" decodes 1 byte; the low 4 bits of 'h' must be zero.
        assert_eq!(decode_url_nopad(b"Zh", 8), Err(Base64Error::NonCanonical));
        assert!(decode_url_nopad(b"Zg", 8).is_ok());
        // Three-symbol group: low 2 bits of the third symbol must be zero.
        assert_eq!(decode_url_nopad(b"Zm9", 8), Err(Base64Error::NonCanonical));
        assert!(decode_url_nopad(b"Zm8", 8).is_ok());
    }

    #[test]
    fn rejects_bad_padding() {
        assert_eq!(decode_std(b"Zg=", 8), Err(Base64Error::InvalidPadding));
        assert_eq!(decode_std(b"Zg===", 8), Err(Base64Error::InvalidPadding));
        assert_eq!(decode_std(b"Z=g=", 8), Err(Base64Error::InvalidPadding));
        assert_eq!(decode_url_nopad(b"Zg==", 8), Err(Base64Error::InvalidPadding));
    }

    #[test]
    fn rejects_impossible_length() {
        assert_eq!(decode_url_nopad(b"Z", 8), Err(Base64Error::InvalidLength));
        assert_eq!(decode_url_nopad(b"Zm9vZ", 8), Err(Base64Error::InvalidLength));
    }

    #[test]
    fn honours_output_bound() {
        let e = encode_url_nopad(&[0u8; 100]);
        assert_eq!(decode_url_nopad(e.as_bytes(), 99), Err(Base64Error::TooLong));
        assert!(decode_url_nopad(e.as_bytes(), 100).is_ok());
    }
}

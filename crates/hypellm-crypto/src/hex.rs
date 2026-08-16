//! Lowercase hexadecimal encoding (RFC 4648 section 8).

/// Error returned by [`decode_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// Input length was not even.
    OddLength,
    /// Input contained a character outside `[0-9a-fA-F]`.
    InvalidCharacter,
    /// Output buffer was not exactly `input.len() / 2` bytes.
    OutputLength,
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::OddLength => "hex input length is odd",
            Self::InvalidCharacter => "hex input contains a non-hex character",
            Self::OutputLength => "hex output buffer has the wrong length",
        };
        f.write_str(s)
    }
}

impl std::error::Error for HexError {}

/// Lowercase hex character for the low nibble of `n`.
///
/// The mask makes the mapping total: the first arm covers `0..=9` and the
/// second is therefore reached only with `10..=15`, so neither addition can
/// leave the ASCII range.
fn digit(n: u8) -> char {
    match n & 0x0f {
        d @ 0..=9 => char::from(b'0' + d),
        d => char::from(b'a' + d - 10),
    }
}

/// Encode `data` as lowercase hex.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(digit(byte >> 4));
        out.push(digit(*byte));
    }
    out
}

/// Encode only the first `n` bytes, for bounded display in logs and traces.
///
/// Specification 17 caps log field sizes; digests appear in decision traces as
/// short prefixes rather than full 64-character strings.
#[must_use]
pub fn encode_prefix(data: &[u8], n: usize) -> String {
    let n = n.min(data.len());
    let (head, _) = data.split_at(n);
    encode(head)
}

const fn val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode hex into a caller-provided buffer. No allocation, explicit bound.
pub fn decode_into(input: &[u8], out: &mut [u8]) -> Result<(), HexError> {
    if input.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    if out.len() * 2 != input.len() {
        return Err(HexError::OutputLength);
    }
    // `out.len() * 2 == input.len()` was just checked, so the zip visits every
    // output byte and every input pair.
    for (slot, pair) in out.iter_mut().zip(input.chunks_exact(2)) {
        let [hi, lo] = pair else {
            // Unreachable: `chunks_exact(2)` yields two-element slices.
            return Err(HexError::OddLength);
        };
        let hi = val(*hi).ok_or(HexError::InvalidCharacter)?;
        let lo = val(*lo).ok_or(HexError::InvalidCharacter)?;
        *slot = (hi << 4) | lo;
    }
    Ok(())
}

/// Decode hex into a `Vec`, bounded by `max_output` bytes.
pub fn decode(input: &[u8], max_output: usize) -> Result<Vec<u8>, HexError> {
    if input.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    // The length is even (checked above), so the number of complete two-byte
    // pairs is exactly the decoded length.
    let n = input.chunks_exact(2).len();
    if n > max_output {
        return Err(HexError::OutputLength);
    }
    let mut out = vec![0u8; n];
    decode_into(input, &mut out)?;
    Ok(out)
}

/// Decode exactly 32 bytes of hex, the common digest case.
pub fn decode_digest(input: &[u8]) -> Result<[u8; 32], HexError> {
    let mut out = [0u8; 32];
    decode_into(input, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data: Vec<u8> = (0..=255u8).collect();
        let s = encode(&data);
        assert_eq!(s.len(), 512);
        assert_eq!(decode(s.as_bytes(), 256).unwrap(), data);
    }

    #[test]
    fn known_values() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(&[0x00]), "00");
        assert_eq!(encode(&[0xff]), "ff");
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn accepts_uppercase_on_decode() {
        assert_eq!(decode(b"DEADbeef", 4).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode(b"abc", 8), Err(HexError::OddLength));
        assert_eq!(decode(b"zz", 8), Err(HexError::InvalidCharacter));
        assert_eq!(decode(b"0011", 1), Err(HexError::OutputLength));
        // Non-ASCII must not be interpreted.
        assert_eq!(decode("ÿÿ".as_bytes(), 8), Err(HexError::InvalidCharacter));
    }

    #[test]
    fn prefix_is_bounded() {
        assert_eq!(encode_prefix(&[0xde, 0xad, 0xbe, 0xef], 2), "dead");
        assert_eq!(encode_prefix(&[0xde], 8), "de");
        assert_eq!(encode_prefix(&[], 8), "");
    }

    #[test]
    fn digest_helper() {
        let d = [7u8; 32];
        assert_eq!(decode_digest(encode(&d).as_bytes()).unwrap(), d);
        assert!(decode_digest(b"00").is_err());
    }
}

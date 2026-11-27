// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), as used by ZIP.

use std::sync::LazyLock;

static TABLE: LazyLock<[u32; 256]> = LazyLock::new(|| {
    std::array::from_fn(|index| {
        let mut crc = u32::try_from(index).unwrap_or_default();
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
        crc
    })
});

/// Computes the CRC-32 of `data`.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let table = &*TABLE;
    let mut crc = u32::MAX;
    for &byte in data {
        let index = usize::from(crc.to_le_bytes()[0] ^ byte);
        crc = table.get(index).copied().unwrap_or_default() ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn matches_reference_values() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }
}

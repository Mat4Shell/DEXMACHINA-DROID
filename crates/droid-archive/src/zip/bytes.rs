// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Bounds-checked little-endian reads from the archive bytes.

/// Returns `len` bytes starting at `offset`, or `None` if any part of the
/// range falls outside `data`.
pub(crate) fn slice(data: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(len).ok()?;
    let end = start.checked_add(len)?;
    data.get(start..end)
}

fn array<const N: usize>(data: &[u8], offset: u64) -> Option<[u8; N]> {
    let len = u64::try_from(N).ok()?;
    slice(data, offset, len)?.try_into().ok()
}

pub(crate) fn u16_at(data: &[u8], offset: u64) -> Option<u16> {
    array(data, offset).map(u16::from_le_bytes)
}

pub(crate) fn u32_at(data: &[u8], offset: u64) -> Option<u32> {
    array(data, offset).map(u32::from_le_bytes)
}

pub(crate) fn u64_at(data: &[u8], offset: u64) -> Option<u64> {
    array(data, offset).map(u64::from_le_bytes)
}

/// Sequential reader over a bounded byte slice.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: u64,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let value = u16_at(self.data, self.pos)?;
        self.pos = self.pos.checked_add(2)?;
        Some(value)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let value = u32_at(self.data, self.pos)?;
        self.pos = self.pos.checked_add(4)?;
        Some(value)
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        let value = u64_at(self.data, self.pos)?;
        self.pos = self.pos.checked_add(8)?;
        Some(value)
    }
}

/// Number of non-overlapping occurrences of `needle` in `haystack`.
pub(crate) fn count_occurrences(haystack: &[u8], needle: &[u8]) -> u64 {
    if needle.is_empty() {
        return 0;
    }
    let mut count: u64 = 0;
    let mut rest = haystack;
    while let Some(pos) = rest.windows(needle.len()).position(|w| w == needle) {
        count = count.saturating_add(1);
        let skip = pos.saturating_add(needle.len());
        rest = rest.get(skip..).unwrap_or_default();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounded() {
        let data = [1u8, 2, 3, 4];
        assert_eq!(u16_at(&data, 0), Some(0x0201));
        assert_eq!(u32_at(&data, 0), Some(0x0403_0201));
        assert_eq!(u32_at(&data, 1), None);
        assert_eq!(u64_at(&data, 0), None);
        assert_eq!(slice(&data, u64::MAX, 2), None);
        assert_eq!(slice(&data, 4, 0), Some(&[][..]));
    }

    #[test]
    fn counts_occurrences() {
        assert_eq!(count_occurrences(b"PKPKxPK", b"PK"), 3);
        assert_eq!(count_occurrences(b"", b"PK"), 0);
        assert_eq!(count_occurrences(b"abc", b""), 0);
    }
}

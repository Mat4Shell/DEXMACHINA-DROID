// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Location of the end of central directory, as Android's libziparchive does
//! it.

use super::bytes::{Cursor, slice, u32_at, u64_at};
use super::error::ZipError;

pub(crate) const EOCD_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
pub(crate) const EOCD_LEN: u64 = 22;
const MAX_COMMENT_LEN: u64 = 0xFFFF;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_LOCATOR_LEN: u64 = 20;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_EOCD_LEN: u64 = 56;
/// Other candidates recorded beyond this number are counted as one.
const MAX_RECORDED_CANDIDATES: usize = 64;

/// The classic end of central directory record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Eocd {
    pub(crate) offset: u64,
    pub(crate) disk: u16,
    pub(crate) cd_disk: u16,
    pub(crate) entries_on_disk: u16,
    pub(crate) entries_total: u16,
    pub(crate) cd_size: u32,
    pub(crate) cd_offset: u32,
    pub(crate) comment_len: u16,
}

impl Eocd {
    /// Whether one of the fields carries a ZIP64 marker. Android treats a
    /// maximal comment length as a marker too.
    pub(crate) fn has_zip64_marker(&self) -> bool {
        self.entries_on_disk == u16::MAX
            || self.entries_total == u16::MAX
            || self.cd_size == u32::MAX
            || self.cd_offset == u32::MAX
            || self.comment_len == u16::MAX
    }

    /// End of the record and of its declared comment.
    pub(crate) fn declared_end(&self) -> u64 {
        self.offset
            .saturating_add(EOCD_LEN)
            .saturating_add(u64::from(self.comment_len))
    }
}

/// The ZIP64 end of central directory record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Zip64Eocd {
    pub(crate) offset: u64,
    pub(crate) disk: u32,
    pub(crate) cd_disk: u32,
    pub(crate) entries_on_disk: u64,
    pub(crate) entries_total: u64,
    pub(crate) cd_size: u64,
    pub(crate) cd_offset: u64,
}

/// Result of the end of central directory search.
pub(crate) struct Located {
    pub(crate) eocd: Eocd,
    /// Offsets of the other signatures within the search window, closest to
    /// the end first.
    pub(crate) other_candidates: Vec<u64>,
}

fn parse_eocd(data: &[u8], offset: u64) -> Option<Eocd> {
    let record = slice(data, offset, EOCD_LEN)?;
    let mut cursor = Cursor::new(record);
    let _signature = cursor.u32()?;
    Some(Eocd {
        offset,
        disk: cursor.u16()?,
        cd_disk: cursor.u16()?,
        entries_on_disk: cursor.u16()?,
        entries_total: cursor.u16()?,
        cd_size: cursor.u32()?,
        cd_offset: cursor.u32()?,
        comment_len: cursor.u16()?,
    })
}

fn is_signature(data: &[u8], offset: u64) -> bool {
    slice(data, offset, 4) == Some(&EOCD_SIGNATURE[..])
}

/// Searches backwards from the end, like libziparchive: the search window is
/// the last `65535 + 22` bytes, a candidate needs 22 bytes after its start,
/// and the first candidate found is the one used.
pub(crate) fn locate(data: &[u8]) -> Result<Located, ZipError> {
    let len = u64::try_from(data.len()).map_err(|_| ZipError::EocdNotFound)?;
    let window = len.min(MAX_COMMENT_LEN.saturating_add(EOCD_LEN));
    let search_start = len.saturating_sub(window);
    let Some(last) = len.checked_sub(EOCD_LEN) else {
        return Err(truncated_or_missing(data, search_start, len));
    };

    let mut found = None;
    let mut pos = last;
    loop {
        if is_signature(data, pos) {
            found = Some(pos);
            break;
        }
        if pos <= search_start {
            break;
        }
        pos = pos.saturating_sub(1);
    }
    let Some(offset) = found else {
        let tail_start = last.saturating_add(1);
        return Err(truncated_or_missing(data, tail_start, len));
    };
    let eocd = parse_eocd(data, offset).ok_or(ZipError::EocdTruncated)?;

    let mut other_candidates = Vec::new();
    let mut pos = offset;
    while pos > search_start && other_candidates.len() < MAX_RECORDED_CANDIDATES {
        pos = pos.saturating_sub(1);
        if is_signature(data, pos) {
            other_candidates.push(pos);
        }
    }
    Ok(Located {
        eocd,
        other_candidates,
    })
}

/// Distinguishes an end record cut short from no end record at all, by looking
/// for a signature in the bytes too close to the end to hold a full record.
fn truncated_or_missing(data: &[u8], from: u64, len: u64) -> ZipError {
    let mut pos = from;
    while pos.saturating_add(4) <= len {
        if is_signature(data, pos) {
            return ZipError::EocdTruncated;
        }
        pos = pos.saturating_add(1);
    }
    ZipError::EocdNotFound
}

/// Whether a ZIP64 locator signature immediately precedes the classic record.
pub(crate) fn has_zip64_locator(data: &[u8], eocd_offset: u64) -> bool {
    eocd_offset
        .checked_sub(ZIP64_LOCATOR_LEN)
        .and_then(|locator| u32_at(data, locator))
        == Some(ZIP64_LOCATOR_SIGNATURE)
}

/// Reads the ZIP64 locator immediately before the classic record, then the
/// ZIP64 record it points to, with the same checks as libziparchive.
pub(crate) fn locate_zip64(data: &[u8], eocd_offset: u64) -> Option<Zip64Eocd> {
    if eocd_offset <= ZIP64_LOCATOR_LEN {
        return None;
    }
    let locator = eocd_offset.checked_sub(ZIP64_LOCATOR_LEN)?;
    if u32_at(data, locator)? != ZIP64_LOCATOR_SIGNATURE {
        return None;
    }
    let record = u64_at(data, locator.checked_add(8)?)?;
    if locator <= ZIP64_EOCD_LEN || record > locator.checked_sub(ZIP64_EOCD_LEN)? {
        return None;
    }
    let bytes = slice(data, record, ZIP64_EOCD_LEN)?;
    let mut cursor = Cursor::new(bytes);
    if cursor.u32()? != ZIP64_EOCD_SIGNATURE {
        return None;
    }
    let _record_size = cursor.u64()?;
    let _version_made_by = cursor.u16()?;
    let _version_needed = cursor.u16()?;
    let zip64 = Zip64Eocd {
        offset: record,
        disk: cursor.u32()?,
        cd_disk: cursor.u32()?,
        entries_on_disk: cursor.u64()?,
        entries_total: cursor.u64()?,
        cd_size: cursor.u64()?,
        cd_offset: cursor.u64()?,
    };
    if record <= zip64.cd_size || zip64.cd_offset > record.checked_sub(zip64.cd_size)? {
        return None;
    }
    Some(zip64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eocd(comment: &[u8]) -> Vec<u8> {
        let mut out = EOCD_SIGNATURE.to_vec();
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
        out.extend_from_slice(comment);
        out
    }

    #[test]
    fn finds_record_with_comment() {
        let mut data = b"prefix".to_vec();
        data.extend(eocd(b"hello"));
        let located = locate(&data).unwrap();
        assert_eq!(located.eocd.offset, 6);
        assert_eq!(located.eocd.comment_len, 5);
        assert!(located.other_candidates.is_empty());
    }

    #[test]
    fn picks_the_candidate_closest_to_the_end() {
        let inner = eocd(b"");
        let data = eocd(&inner);
        let located = locate(&data).unwrap();
        assert_eq!(located.eocd.offset, 22);
        assert_eq!(located.other_candidates, vec![0]);
    }

    #[test]
    fn distinguishes_truncated_from_missing() {
        assert_eq!(locate(b"").err(), Some(ZipError::EocdNotFound));
        assert_eq!(locate(&[0u8; 100]).err(), Some(ZipError::EocdNotFound));
        let mut data = vec![0u8; 30];
        data.extend_from_slice(&EOCD_SIGNATURE);
        data.extend_from_slice(&[0; 10]);
        assert_eq!(locate(&data).err(), Some(ZipError::EocdTruncated));
        assert_eq!(locate(&EOCD_SIGNATURE).err(), Some(ZipError::EocdTruncated));
    }

    #[test]
    fn ignores_signatures_outside_the_window() {
        let mut data = eocd(b"");
        data.extend(vec![0u8; 70_000]);
        assert_eq!(locate(&data).err(), Some(ZipError::EocdNotFound));
    }
}

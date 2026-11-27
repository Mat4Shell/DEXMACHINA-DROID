// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Reading entry content in memory, under the configured limits.

use std::cell::Cell;

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};

use super::anomaly::{Anomaly, AnomalyKind};
use super::bytes::{Cursor, slice, u32_at};
use super::crc32::crc32;
use super::error::{LimitKind, ReadError};
use super::{DATA_DESCRIPTOR_SIGNATURE, Entry, METHOD_DEFLATED};
use crate::Limits;

/// The content of an entry, with the anomalies found while reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryContent {
    /// The uncompressed bytes.
    pub data: Vec<u8>,
    /// Anomalies found while reading the content.
    pub anomalies: Vec<Anomaly>,
}

/// Whether libziparchive reads 64-bit sizes in the data descriptor.
pub(crate) fn is_zip64_sized(entry: &Entry) -> bool {
    let max = u64::from(u32::MAX);
    entry.compressed_size >= max || entry.uncompressed_size >= max
}

pub(crate) fn read_entry(
    data: &[u8],
    entry: &Entry,
    limits: &Limits,
    produced: &Cell<u64>,
) -> Result<EntryContent, ReadError> {
    let data_offset = entry.data_offset.ok_or(ReadError::NotLocatable)?;
    let size = entry.uncompressed_size;
    check_limit(LimitKind::EntrySize, size, limits.max_entry_size)?;
    let total = produced.get().saturating_add(size);
    check_limit(LimitKind::TotalSize, total, limits.max_total_size)?;

    let mut anomalies = Vec::new();
    let content = if entry.method == METHOD_DEFLATED {
        check_ratio(entry, limits)?;
        let input =
            slice(data, data_offset, entry.compressed_size).ok_or(ReadError::OutOfBounds)?;
        let (content, unused) = inflate(input, size)?;
        if unused > 0 {
            anomalies.push(Anomaly::entry(
                entry.index,
                entry.component,
                AnomalyKind::DeflateTrailingData { len: unused },
            ));
        }
        content
    } else {
        // Stored, and any unsupported method: Android's resource loader maps
        // the uncompressed size from the data offset.
        let raw = slice(data, data_offset, size).ok_or(ReadError::OutOfBounds)?;
        let mut content = Vec::new();
        content
            .try_reserve_exact(raw.len())
            .map_err(|_| ReadError::Allocation)?;
        content.extend_from_slice(raw);
        content
    };
    produced.set(total);

    let actual = crc32(&content);
    if actual != entry.crc32 {
        anomalies.push(Anomaly::entry(
            entry.index,
            entry.component,
            AnomalyKind::CrcMismatch {
                declared: entry.crc32,
                actual,
            },
        ));
    }
    if entry.has_data_descriptor
        && let Some(kind) = check_data_descriptor(data, entry, data_offset)
    {
        anomalies.push(Anomaly::entry(entry.index, entry.component, kind));
    }
    Ok(EntryContent {
        data: content,
        anomalies,
    })
}

fn check_limit(limit: LimitKind, value: u64, max: u64) -> Result<(), ReadError> {
    if value > max {
        return Err(ReadError::LimitExceeded { limit, value, max });
    }
    Ok(())
}

fn check_ratio(entry: &Entry, limits: &Limits) -> Result<(), ReadError> {
    let size = entry.uncompressed_size;
    if size <= limits.compression_ratio_min_size {
        return Ok(());
    }
    let compressed = entry.compressed_size.max(1);
    let allowed = compressed.saturating_mul(limits.max_compression_ratio);
    if size > allowed {
        return Err(ReadError::LimitExceeded {
            limit: LimitKind::CompressionRatio,
            value: size.checked_div(compressed).unwrap_or(u64::MAX),
            max: limits.max_compression_ratio,
        });
    }
    Ok(())
}

/// Inflates a raw deflate stream that must produce exactly `declared` bytes.
/// The output buffer holds one byte more than declared, so that a stream
/// producing more is detected without ever growing the buffer. Returns the
/// content and the number of input bytes left after the end of the stream.
fn inflate(input: &[u8], declared: u64) -> Result<(Vec<u8>, u64), ReadError> {
    let capacity = usize::try_from(declared)
        .ok()
        .and_then(|len| len.checked_add(1))
        .ok_or(ReadError::Allocation)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| ReadError::Allocation)?;
    output.resize(capacity, 0);

    let mut state = Box::<DecompressorOxide>::default();
    let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let (status, consumed, written) = decompress(&mut state, input, &mut output, 0, flags);
    let written_u64 = u64::try_from(written).unwrap_or(u64::MAX);
    match status {
        TINFLStatus::Done if written_u64 == declared => {
            output.truncate(written);
            let unused = input.len().saturating_sub(consumed);
            Ok((output, u64::try_from(unused).unwrap_or(u64::MAX)))
        }
        TINFLStatus::Done | TINFLStatus::HasMoreOutput => Err(ReadError::SizeMismatch {
            declared,
            produced: written_u64,
        }),
        _ => Err(ReadError::InvalidDeflate),
    }
}

/// Validates the data descriptor like libziparchive: 24 bytes must be
/// readable after the data, the signature is optional, and the sizes are
/// 64-bit when a central directory size does not fit in 32 bits.
fn check_data_descriptor(data: &[u8], entry: &Entry, data_offset: u64) -> Option<AnomalyKind> {
    let at = data_offset.checked_add(entry.data_len())?;
    let Some(bytes) = slice(data, at, 24) else {
        return Some(AnomalyKind::DataDescriptorUnreadable);
    };
    let skip = if u32_at(bytes, 0) == Some(DATA_DESCRIPTOR_SIGNATURE) {
        4
    } else {
        0
    };
    let mut cursor = Cursor::new(bytes.get(skip..)?);
    let crc = cursor.u32()?;
    let (compressed, uncompressed) = if is_zip64_sized(entry) {
        (cursor.u64()?, cursor.u64()?)
    } else {
        (u64::from(cursor.u32()?), u64::from(cursor.u32()?))
    };
    let matches = crc == entry.crc32
        && compressed == entry.compressed_size
        && uncompressed == entry.uncompressed_size;
    (!matches).then_some(AnomalyKind::DataDescriptorMismatch)
}

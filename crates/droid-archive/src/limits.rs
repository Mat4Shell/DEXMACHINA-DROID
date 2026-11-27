// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Resource limits applied while reading an archive.

/// Upper bounds on the resources an archive may consume.
///
/// Every limit is checked against values declared by the archive before any
/// work is done, then enforced again on what is actually produced. Only the
/// number of entries and the size of the central directory prevent an archive
/// from being opened; the other limits apply to reading one entry. Entry names
/// are not limited, since the format bounds them to 65535 bytes: unusually
/// long names are reported as anomalies instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of entries declared by the central directory.
    pub max_entries: u64,
    /// Maximum size of the central directory, in bytes. It bounds the memory
    /// used to hold entry names, whatever the size of the input.
    pub max_central_directory_size: u64,
    /// Maximum uncompressed size of a single entry, in bytes.
    pub max_entry_size: u64,
    /// Maximum number of uncompressed bytes produced by all reads from one
    /// archive, in bytes.
    pub max_total_size: u64,
    /// Maximum ratio between the uncompressed and the compressed size of a
    /// deflated entry.
    pub max_compression_ratio: u64,
    /// Entries whose uncompressed size is at most this many bytes are exempt
    /// from the compression ratio check, since small files of repeated bytes
    /// legitimately compress very well.
    pub compression_ratio_min_size: u64,
}

impl Limits {
    /// Default limits, sized for real-world Android applications.
    pub const DEFAULT: Self = Self {
        max_entries: 100_000,
        max_central_directory_size: 64 * 1024 * 1024,
        max_entry_size: 512 * 1024 * 1024,
        max_total_size: 4 * 1024 * 1024 * 1024,
        max_compression_ratio: 200,
        compression_ratio_min_size: 1024 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

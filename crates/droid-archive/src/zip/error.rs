// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Errors that stop the reading of an archive or of an entry.

use std::error::Error;
use std::fmt;

/// The limit that a value exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitKind {
    /// [`Limits::max_entries`](crate::Limits::max_entries).
    Entries,
    /// [`Limits::max_central_directory_size`](crate::Limits::max_central_directory_size).
    CentralDirectorySize,
    /// [`Limits::max_entry_size`](crate::Limits::max_entry_size).
    EntrySize,
    /// [`Limits::max_total_size`](crate::Limits::max_total_size).
    TotalSize,
    /// [`Limits::max_compression_ratio`](crate::Limits::max_compression_ratio).
    CompressionRatio,
}

/// Why an archive could not be opened at all.
///
/// Each of these conditions also makes Android refuse the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZipError {
    /// No end of central directory record was found.
    EocdNotFound,
    /// An end of central directory signature was found too close to the end
    /// of the input for a complete record.
    EocdTruncated,
    /// The ZIP64 end of central directory is missing or malformed.
    Zip64Invalid,
    /// The central directory does not fit before its end record.
    CentralDirectoryOutOfBounds,
    /// The central directory ends before all declared entries were read.
    CentralDirectoryTruncated {
        /// Index of the entry that could not be read.
        entry: u64,
    },
    /// A central directory record has no valid signature.
    BadCentralDirectorySignature {
        /// Index of the record.
        entry: u64,
    },
    /// The ZIP64 extended information needed to locate an entry is missing
    /// or malformed.
    Zip64ExtraInvalid {
        /// Index of the record.
        entry: u64,
    },
    /// A value declared by the archive exceeds a configured limit.
    LimitExceeded {
        /// The limit exceeded.
        limit: LimitKind,
        /// The declared value.
        value: u64,
        /// The configured maximum.
        max: u64,
    },
}

impl ZipError {
    /// Stable identifier of the error. Codes are never reused nor renamed.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EocdNotFound => "zip.error.eocd_not_found",
            Self::EocdTruncated => "zip.error.eocd_truncated",
            Self::Zip64Invalid => "zip.error.zip64_invalid",
            Self::CentralDirectoryOutOfBounds => "zip.error.cd_out_of_bounds",
            Self::CentralDirectoryTruncated { .. } => "zip.error.cd_truncated",
            Self::BadCentralDirectorySignature { .. } => "zip.error.cd_bad_signature",
            Self::Zip64ExtraInvalid { .. } => "zip.error.zip64_extra_invalid",
            Self::LimitExceeded { limit, .. } => limit_code(*limit),
        }
    }
}

const fn limit_code(limit: LimitKind) -> &'static str {
    match limit {
        LimitKind::Entries => "zip.limit.entries",
        LimitKind::CentralDirectorySize => "zip.limit.central_directory_size",
        LimitKind::EntrySize => "zip.limit.entry_size",
        LimitKind::TotalSize => "zip.limit.total_size",
        LimitKind::CompressionRatio => "zip.limit.compression_ratio",
    }
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EocdNotFound => f.write_str("end of central directory not found"),
            Self::EocdTruncated => f.write_str("end of central directory is truncated"),
            Self::Zip64Invalid => f.write_str("invalid ZIP64 end of central directory"),
            Self::CentralDirectoryOutOfBounds => {
                f.write_str("central directory does not fit before its end record")
            }
            Self::CentralDirectoryTruncated { entry } => {
                write!(f, "central directory ends before entry {entry}")
            }
            Self::BadCentralDirectorySignature { entry } => {
                write!(f, "bad central directory signature for entry {entry}")
            }
            Self::Zip64ExtraInvalid { entry } => {
                write!(f, "invalid ZIP64 extended information for entry {entry}")
            }
            Self::LimitExceeded { limit, value, max } => {
                write!(f, "{} is {value}, limit is {max}", limit_name(*limit))
            }
        }
    }
}

impl Error for ZipError {}

const fn limit_name(limit: LimitKind) -> &'static str {
    match limit {
        LimitKind::Entries => "entry count",
        LimitKind::CentralDirectorySize => "central directory size",
        LimitKind::EntrySize => "entry size",
        LimitKind::TotalSize => "total uncompressed size",
        LimitKind::CompressionRatio => "compression ratio",
    }
}

/// Why the content of an entry could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReadError {
    /// No entry has this index.
    NoSuchEntry,
    /// The entry's data cannot be located: its local header is missing, out
    /// of range or malformed.
    NotLocatable,
    /// The entry's data extends past the end of the input.
    OutOfBounds,
    /// A declared or produced size exceeds a configured limit.
    LimitExceeded {
        /// The limit exceeded.
        limit: LimitKind,
        /// The value that exceeded it.
        value: u64,
        /// The configured maximum.
        max: u64,
    },
    /// The deflate stream is invalid or truncated.
    InvalidDeflate,
    /// The deflate stream does not produce the declared uncompressed size.
    SizeMismatch {
        /// Declared uncompressed size.
        declared: u64,
        /// Size produced, or `declared + 1` if the stream produces more.
        produced: u64,
    },
    /// The memory for the content could not be allocated.
    Allocation,
}

impl ReadError {
    /// Stable identifier of the error. Codes are never reused nor renamed.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoSuchEntry => "zip.read.no_such_entry",
            Self::NotLocatable => "zip.read.not_locatable",
            Self::OutOfBounds => "zip.read.out_of_bounds",
            Self::LimitExceeded { limit, .. } => limit_code(*limit),
            Self::InvalidDeflate => "zip.read.invalid_deflate",
            Self::SizeMismatch { .. } => "zip.read.size_mismatch",
            Self::Allocation => "zip.read.allocation",
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchEntry => f.write_str("no such entry"),
            Self::NotLocatable => f.write_str("entry data cannot be located"),
            Self::OutOfBounds => f.write_str("entry data extends past the end of the input"),
            Self::LimitExceeded { limit, value, max } => {
                write!(f, "{} is {value}, limit is {max}", limit_name(*limit))
            }
            Self::InvalidDeflate => f.write_str("invalid deflate stream"),
            Self::SizeMismatch { declared, produced } => write!(
                f,
                "deflate stream produced {produced} bytes, {declared} declared"
            ),
            Self::Allocation => f.write_str("allocation failed"),
        }
    }
}

impl Error for ReadError {}

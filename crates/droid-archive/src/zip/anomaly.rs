// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Typed anomalies found while reading an archive.
//!
//! An anomaly is a construction that Android rejects, that Android reads
//! differently from a general-purpose ZIP reader, or that is unusual enough to
//! deserve the attention of an analyst. Anomalies never stop the parser on
//! their own: the archive is still exposed as Android would see it, and as far
//! as possible beyond the point where Android would give up.

use std::fmt;

use super::component::Component;

/// What an anomaly means for an Android device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Impact {
    /// Android refuses to open the archive.
    ArchiveRejected,
    /// The archive opens, but Android fails when it accesses this entry.
    EntryRejected,
    /// Android accepts the construction, but a general-purpose ZIP reader
    /// sees different content, or fails. This is the signature of most
    /// anti-analysis tricks.
    Divergence,
    /// Android and general-purpose readers agree, but the construction is
    /// hostile or very unusual.
    Suspicious,
    /// Worth recording, with no effect on how the archive is read.
    Informational,
}

impl Impact {
    /// Stable identifier of the impact.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArchiveRejected => "archive_rejected",
            Self::EntryRejected => "entry_rejected",
            Self::Divergence => "divergence",
            Self::Suspicious => "suspicious",
            Self::Informational => "informational",
        }
    }
}

/// The local header field that disagrees with the central directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalField {
    /// CRC-32 of the uncompressed data.
    Crc32,
    /// Compressed size.
    CompressedSize,
    /// Uncompressed size.
    UncompressedSize,
}

/// The kind of an anomaly, with the values that characterize it.
///
/// Offsets are absolute positions in the input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The end of central directory record plus its comment does not end
    /// exactly at the end of the input: data was appended after the archive,
    /// or the comment length points past the end.
    EocdLengthMismatch {
        /// Where the record and its declared comment end.
        declared_end: u64,
        /// Length of the input.
        actual_len: u64,
    },
    /// Other end of central directory signatures were found before the one
    /// Android selects. A reader that searches differently may select one of
    /// them and see another archive.
    EocdMultipleCandidates {
        /// Offsets of the other signatures, closest to the end first.
        offsets: Vec<u64>,
    },
    /// The archive has a non-empty comment.
    EocdComment {
        /// Length of the comment, in bytes.
        len: u64,
    },
    /// The multi-disk fields of the end of central directory record are not
    /// those of a single-disk archive. Android ignores them; some readers
    /// reject the archive.
    EocdMultiDisk {
        /// Number of this disk.
        disk: u32,
        /// Disk where the central directory starts.
        cd_disk: u32,
        /// Entries declared on this disk.
        entries_on_disk: u64,
        /// Entries declared in total.
        entries_total: u64,
    },
    /// The archive uses the ZIP64 end of central directory. Android's
    /// APK Signature Scheme v2 and v3 verifiers reject ZIP64 archives.
    Zip64,
    /// A ZIP64 marker in the end of central directory record made Android
    /// look for a ZIP64 locator that is not there. A 65535-byte comment is
    /// enough to trigger this. Other readers use the classic record.
    Zip64LocatorMissing,
    /// The classic end of central directory record and the ZIP64 record
    /// disagree on a value that is not a ZIP64 marker.
    Zip64EocdMismatch,
    /// The central directory declares no entry. Android refuses empty
    /// archives.
    EmptyArchive,
    /// The input does not start with a local file header. Android requires
    /// one at offset zero, so prepended data makes it reject the archive.
    PrefixData {
        /// Length of the data before the first local header.
        len: u64,
    },
    /// The central directory is not where the end of central directory says,
    /// but is found further, as if the archive had been prepended with
    /// `delta` bytes without adjusting its offsets. Android rejects it; some
    /// readers compensate and open it. Every offset of the archive has been
    /// shifted by `delta` to keep reading.
    OffsetsShifted {
        /// Number of prepended bytes.
        delta: u64,
    },
    /// More central directory records follow the number of entries declared
    /// by the end of central directory. Android ignores them; a reader that
    /// walks the whole central directory sees extra entries.
    HiddenCentralRecords {
        /// Number of extra records.
        count: u64,
    },
    /// Bytes remain in the central directory after the declared entries, and
    /// they are not central directory records.
    CentralDirectoryTrailingBytes {
        /// Number of bytes.
        len: u64,
    },
    /// The central directory is not immediately followed by the end of
    /// central directory record. Android's APK Signature Scheme v2 and v3
    /// verifiers reject such archives.
    CentralDirectoryGap {
        /// Offset of the gap.
        offset: u64,
        /// Length of the gap.
        len: u64,
    },
    /// Bytes before the central directory that belong to no entry and are not
    /// the APK Signing Block. Zero-filled gaps are usually alignment padding,
    /// for instance before the APK Signing Block.
    UnaccountedData {
        /// Offset of the bytes.
        offset: u64,
        /// Number of bytes.
        len: u64,
        /// Whether all the bytes are zero.
        zero_filled: bool,
    },
    /// Local file header signatures found in bytes that belong to no entry of
    /// the central directory. A streaming reader, which follows local headers,
    /// sees entries that Android does not.
    HiddenLocalHeaders {
        /// Offset of the bytes that contain them.
        offset: u64,
        /// Number of signatures found.
        count: u64,
    },
    /// The bytes before the central directory end with the APK Signing Block
    /// magic, but its size fields are inconsistent.
    SigningBlockMalformed,
    /// Two entries have the same name. Android refuses the archive; other
    /// readers keep one or the other.
    DuplicateName {
        /// Index of the first entry with this name.
        first: usize,
    },
    /// Two entry names differ only by ASCII case. They collide on
    /// case-insensitive file systems. Common in applications whose resource
    /// names were shortened by an obfuscator.
    CaseCollision {
        /// Index of the first entry with this name.
        first: usize,
    },
    /// The name contains a NUL byte or is not UTF-8 by Android's definition.
    /// Android refuses the archive.
    InvalidName,
    /// The name passes Android's permissive UTF-8 check (overlong forms,
    /// surrogates, five-byte sequences) but is not valid UTF-8.
    NameNotStrictUtf8,
    /// The entry has an empty name.
    EmptyName,
    /// The name is at least [`LONG_NAME_LEN`](super::LONG_NAME_LEN) bytes
    /// long, or one of its path components is longer than
    /// [`LONG_NAME_COMPONENT_LEN`](super::LONG_NAME_COMPONENT_LEN) bytes.
    /// Android's native library installer skips such names, except 65535-byte
    /// names on devices without the fix for CVE-2026-58995 (see
    /// [`NameLengthOverflow`](Self::NameLengthOverflow)), and no file system
    /// can hold them.
    LongName {
        /// Length of the name, in bytes.
        len: u64,
        /// Length of its longest path component, in bytes.
        longest_component: u64,
    },
    /// A 65535-byte name that crashes the native library installer of devices
    /// without the Android 2026-11-01 security patch level: CVE-2026-58995.
    ///
    /// `ZipFileRO::getEntryFileName` stored the name length plus one in a
    /// `uint16_t`, which wraps to 0 for the longest name a ZIP archive can
    /// hold. The check against the caller's 4096-byte buffer then passes, and
    /// `memcpy` receives a length of `SIZE_MAX`: it writes past the buffer
    /// until it faults. The installer (`NativeLibraryHelper`, in
    /// `system_server` during an installation) calls it on every entry that
    /// the ZIP library returns for two scans, before looking at the rest of
    /// the name: names that start with `lib/` (native libraries, scanned on
    /// every device) and names that end with `.bc` (RenderScript bitcode,
    /// scanned on 64-bit devices unless the manifest sets
    /// `android:multiArch` or an ABI is forced). The fix computes the size as
    /// a `size_t`, so patched devices skip the entry.
    ///
    /// Reported only when the ZIP library returns the entry to these scans:
    /// a name that Android accepts, and a local header that agrees with the
    /// central directory. The installation reaches the scans only if Android
    /// opens the archive ([`android_accepts`](super::ZipArchive::android_accepts)).
    /// Android 5.x scanned every entry, so that any 65535-byte name crashes
    /// it; that behaviour is not modelled.
    ///
    /// The impact is [`Impact::Suspicious`], from the behaviour of a patched
    /// Android: the installer skips the entry without failing, as it skips
    /// every name of 4096 bytes or more, and the archive installs. The
    /// vulnerability is carried by
    /// [`known_vulnerabilities`](Self::known_vulnerabilities).
    NameLengthOverflow {
        /// The name starts with `lib/`.
        lib_prefix: bool,
        /// The name ends with `.bc`.
        bc_suffix: bool,
    },
    /// The name contains a `..` path component.
    PathTraversal,
    /// The name is an absolute path (leading `/` or `\`, or a drive letter).
    AbsolutePath,
    /// The name contains a backslash, a path separator on Windows.
    Backslash,
    /// The entry is a Unix symbolic link.
    Symlink,
    /// A DEX entry that ART never loads: ART opens `classes.dex`, then
    /// `classes2.dex`, `classes3.dex` and so on, and stops at the first name
    /// that is missing from the archive. Build tools number DEX files without
    /// gaps; code placed after a gap is invisible to the application's class
    /// loader but not to tools that read every DEX file.
    DexUnreachable {
        /// Position of the first missing name in ART's loading order: 1 for
        /// `classes.dex`, `N` for `classesN.dex`.
        missing: u64,
    },
    /// The local header offset is at or past the central directory. Android
    /// refuses the archive.
    LocalHeaderOutOfRange,
    /// The local header does not fit before the central directory.
    LocalHeaderTruncated,
    /// No local header signature at the offset given by the central
    /// directory.
    LocalHeaderMissing,
    /// The local header names another file than the central directory.
    /// Android cannot read the entry; a streaming reader sees the local name.
    LocalNameMismatch,
    /// The local header declares another compression method. Android uses the
    /// central directory and ignores it; a streaming reader does not.
    LocalMethodMismatch {
        /// Method in the central directory.
        central: u16,
        /// Method in the local header.
        local: u16,
    },
    /// The local header declares other general purpose flags.
    LocalFlagsMismatch {
        /// Flags in the central directory.
        central: u16,
        /// Flags in the local header.
        local: u16,
    },
    /// The local header declares another CRC or size. Without a data
    /// descriptor Android cannot read the entry; with one, Android ignores the
    /// local values but a streaming reader may use them.
    LocalValueMismatch {
        /// The field that differs.
        field: LocalField,
        /// Whether the local header announces a data descriptor.
        data_descriptor: bool,
    },
    /// The local header uses ZIP64 sizes inconsistently.
    LocalZip64Invalid,
    /// The ZIP64 extended information of the central directory record is
    /// missing or malformed.
    Zip64ExtraInvalid,
    /// The entry header or data extends past the start of the central
    /// directory.
    DataOutOfRange,
    /// The encryption flag is set. Android ignores it and reads the entry in
    /// clear; general-purpose readers ask for a password or reject the entry.
    EncryptedFlag {
        /// Whether the strong encryption flag is set too.
        strong: bool,
    },
    /// The compression method is neither stored nor deflate. The resource
    /// loader reads such an entry as stored, ART and the native library
    /// installer fail to extract it, the JAR signature verifier inflates it,
    /// and general-purpose readers reject it.
    UnsupportedMethod {
        /// The declared method.
        method: u16,
    },
    /// A stored entry declares different compressed and uncompressed sizes.
    /// Android reads the uncompressed size.
    StoredSizeMismatch,
    /// The entry's bytes overlap those of another entry.
    Overlap {
        /// Index of the other entry.
        other: usize,
    },
    /// The CRC-32 of the content does not match the declared value. Android
    /// does not check it; general-purpose readers do.
    CrcMismatch {
        /// Declared CRC-32.
        declared: u32,
        /// CRC-32 of the content.
        actual: u32,
    },
    /// The data descriptor disagrees with the central directory. The ZIP
    /// library's extraction fails (ART, native libraries); the resource loader
    /// and the JAR signature verifier do not check it.
    DataDescriptorMismatch,
    /// The data descriptor announced by the local header cannot be read.
    DataDescriptorUnreadable,
    /// Compressed bytes remain after the end of the deflate stream.
    DeflateTrailingData {
        /// Number of unused bytes.
        len: u64,
    },
}

impl AnomalyKind {
    /// Stable identifier of the anomaly kind. Codes are never reused nor
    /// renamed.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EocdLengthMismatch { .. } => "zip.eocd.length_mismatch",
            Self::EocdMultipleCandidates { .. } => "zip.eocd.multiple_candidates",
            Self::EocdComment { .. } => "zip.eocd.comment",
            Self::EocdMultiDisk { .. } => "zip.eocd.multi_disk",
            Self::Zip64 => "zip.zip64.used",
            Self::Zip64LocatorMissing => "zip.zip64.locator_missing",
            Self::Zip64EocdMismatch => "zip.zip64.eocd_mismatch",
            Self::EmptyArchive => "zip.empty",
            Self::PrefixData { .. } => "zip.prefix_data",
            Self::OffsetsShifted { .. } => "zip.offsets_shifted",
            Self::HiddenCentralRecords { .. } => "zip.cd.hidden_records",
            Self::CentralDirectoryTrailingBytes { .. } => "zip.cd.trailing_bytes",
            Self::CentralDirectoryGap { .. } => "zip.cd.gap_before_eocd",
            Self::UnaccountedData { .. } => "zip.gap.unaccounted",
            Self::HiddenLocalHeaders { .. } => "zip.gap.hidden_local_headers",
            Self::SigningBlockMalformed => "zip.signing_block.malformed",
            Self::DuplicateName { .. } => "zip.entry.duplicate_name",
            Self::CaseCollision { .. } => "zip.entry.case_collision",
            Self::InvalidName => "zip.entry.invalid_name",
            Self::NameNotStrictUtf8 => "zip.entry.name_not_utf8",
            Self::EmptyName => "zip.entry.empty_name",
            Self::LongName { .. } => "zip.entry.long_name",
            Self::NameLengthOverflow { .. } => "zip.entry.name_length_overflow",
            Self::PathTraversal => "zip.entry.path_traversal",
            Self::AbsolutePath => "zip.entry.absolute_path",
            Self::Backslash => "zip.entry.backslash",
            Self::Symlink => "zip.entry.symlink",
            Self::LocalHeaderOutOfRange => "zip.entry.lfh_out_of_range",
            Self::LocalHeaderTruncated => "zip.entry.lfh_truncated",
            Self::LocalHeaderMissing => "zip.entry.lfh_missing",
            Self::LocalNameMismatch => "zip.entry.lfh_name_mismatch",
            Self::LocalMethodMismatch { .. } => "zip.entry.lfh_method_mismatch",
            Self::LocalFlagsMismatch { .. } => "zip.entry.lfh_flags_mismatch",
            Self::LocalValueMismatch { .. } => "zip.entry.lfh_value_mismatch",
            Self::LocalZip64Invalid => "zip.entry.lfh_zip64_invalid",
            Self::Zip64ExtraInvalid => "zip.entry.zip64_extra_invalid",
            Self::DataOutOfRange => "zip.entry.data_out_of_range",
            Self::EncryptedFlag { .. } => "zip.entry.encrypted_flag",
            Self::UnsupportedMethod { .. } => "zip.entry.unsupported_method",
            Self::StoredSizeMismatch => "zip.entry.stored_size_mismatch",
            Self::Overlap { .. } => "zip.entry.overlap",
            Self::DexUnreachable { .. } => "zip.entry.dex_unreachable",
            Self::CrcMismatch { .. } => "zip.entry.crc_mismatch",
            Self::DataDescriptorMismatch => "zip.entry.data_descriptor_mismatch",
            Self::DataDescriptorUnreadable => "zip.entry.data_descriptor_unreadable",
            Self::DeflateTrailingData { .. } => "zip.entry.deflate_trailing_data",
        }
    }

    /// Known vulnerabilities of Android that the construction triggers on
    /// devices without their fix, as CVE identifiers. Empty for most kinds.
    ///
    /// This is independent of the [impact](Self::impact_in), which describes
    /// how an up-to-date Android reads the archive.
    pub const fn known_vulnerabilities(&self) -> &'static [&'static str] {
        match self {
            Self::NameLengthOverflow { .. } => &["CVE-2026-58995"],
            _ => &[],
        }
    }

    /// What the anomaly means for an Android device, when the given
    /// component reads the entry. `None` stands for the ZIP library that all
    /// components share, which is the only reader of the archive structure.
    pub const fn impact_in(&self, component: Option<Component>) -> Impact {
        match (self, component) {
            (Self::UnsupportedMethod { .. }, Some(Component::Dex | Component::NativeLibraries)) => {
                return Impact::EntryRejected;
            }
            (
                Self::DataDescriptorMismatch | Self::DataDescriptorUnreadable,
                Some(Component::Resources | Component::JarSignature),
            ) => return Impact::Divergence,
            _ => {}
        }
        match self {
            Self::EocdLengthMismatch { .. }
            | Self::Zip64LocatorMissing
            | Self::EmptyArchive
            | Self::PrefixData { .. }
            | Self::OffsetsShifted { .. }
            | Self::DuplicateName { .. }
            | Self::InvalidName
            | Self::LocalHeaderOutOfRange => Impact::ArchiveRejected,
            Self::LocalHeaderTruncated
            | Self::LocalHeaderMissing
            | Self::LocalNameMismatch
            | Self::LocalZip64Invalid
            | Self::Zip64ExtraInvalid
            | Self::DataOutOfRange
            | Self::DataDescriptorMismatch
            | Self::DataDescriptorUnreadable => Impact::EntryRejected,
            Self::LocalValueMismatch {
                data_descriptor, ..
            } => {
                if *data_descriptor {
                    Impact::Divergence
                } else {
                    Impact::EntryRejected
                }
            }
            Self::UnaccountedData { zero_filled, .. } => {
                if *zero_filled {
                    Impact::Informational
                } else {
                    Impact::Suspicious
                }
            }
            Self::EocdMultipleCandidates { .. }
            | Self::EocdMultiDisk { .. }
            | Self::Zip64EocdMismatch
            | Self::HiddenCentralRecords { .. }
            | Self::HiddenLocalHeaders { .. }
            | Self::NameNotStrictUtf8
            | Self::LocalMethodMismatch { .. }
            | Self::LocalFlagsMismatch { .. }
            | Self::EncryptedFlag { .. }
            | Self::UnsupportedMethod { .. }
            | Self::StoredSizeMismatch
            | Self::CrcMismatch { .. }
            | Self::DeflateTrailingData { .. } => Impact::Divergence,
            Self::Zip64
            | Self::CentralDirectoryTrailingBytes { .. }
            | Self::CentralDirectoryGap { .. }
            | Self::SigningBlockMalformed
            | Self::EmptyName
            | Self::LongName { .. }
            | Self::NameLengthOverflow { .. }
            | Self::PathTraversal
            | Self::AbsolutePath
            | Self::Backslash
            | Self::Symlink
            | Self::Overlap { .. }
            | Self::DexUnreachable { .. } => Impact::Suspicious,
            Self::EocdComment { .. } | Self::CaseCollision { .. } => Impact::Informational,
        }
    }
}

impl fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EocdLengthMismatch {
                declared_end,
                actual_len,
            } => write!(
                f,
                "end of central directory ends at {declared_end}, input is {actual_len} bytes long"
            ),
            Self::EocdMultipleCandidates { offsets } => write!(
                f,
                "{} other end of central directory signature(s) found",
                offsets.len()
            ),
            Self::EocdComment { len } => write!(f, "archive comment of {len} bytes"),
            Self::EocdMultiDisk {
                disk,
                cd_disk,
                entries_on_disk,
                entries_total,
            } => write!(
                f,
                "multi-disk fields: disk {disk}, central directory disk {cd_disk}, \
                 {entries_on_disk} entries on disk, {entries_total} in total"
            ),
            Self::Zip64 => f.write_str("ZIP64 end of central directory in use"),
            Self::Zip64LocatorMissing => {
                f.write_str("ZIP64 marker without a ZIP64 end of central directory locator")
            }
            Self::Zip64EocdMismatch => {
                f.write_str("classic and ZIP64 end of central directory records disagree")
            }
            Self::EmptyArchive => f.write_str("central directory declares no entry"),
            Self::PrefixData { len } => write!(f, "{len} bytes before the first local header"),
            Self::OffsetsShifted { delta } => {
                write!(f, "archive offsets are shifted by {delta} prepended bytes")
            }
            Self::HiddenCentralRecords { count } => write!(
                f,
                "{count} central directory record(s) past the declared entry count"
            ),
            Self::CentralDirectoryTrailingBytes { len } => {
                write!(f, "{len} unused bytes at the end of the central directory")
            }
            Self::CentralDirectoryGap { offset, len } => write!(
                f,
                "{len} bytes at {offset} between the central directory and its end record"
            ),
            Self::UnaccountedData {
                offset,
                len,
                zero_filled,
            } => {
                let zeros = if *zero_filled { " (all zero)" } else { "" };
                write!(f, "{len} bytes at {offset} belong to no entry{zeros}")
            }
            Self::HiddenLocalHeaders { offset, count } => write!(
                f,
                "{count} local header signature(s) in unreferenced bytes at {offset}"
            ),
            Self::SigningBlockMalformed => f.write_str("malformed APK Signing Block"),
            Self::DuplicateName { first } => write!(f, "same name as entry {first}"),
            Self::CaseCollision { first } => {
                write!(f, "name differs from entry {first} only by case")
            }
            Self::InvalidName => f.write_str("name contains NUL or is not UTF-8"),
            Self::NameNotStrictUtf8 => f.write_str("name is not strictly valid UTF-8"),
            Self::EmptyName => f.write_str("empty name"),
            Self::LongName {
                len,
                longest_component,
            } => write!(
                f,
                "name of {len} bytes, longest path component of {longest_component} bytes"
            ),
            Self::NameLengthOverflow {
                lib_prefix,
                bc_suffix,
            } => {
                let scans = match (lib_prefix, bc_suffix) {
                    (true, true) => "lib/ and .bc scans",
                    (true, false) => "lib/ scan",
                    _ => ".bc scan",
                };
                write!(
                    f,
                    "65535-byte name overflows the name copy of the native library \
                     installer ({scans}) on Android before the 2026-11-01 security \
                     patch level (CVE-2026-58995)"
                )
            }
            Self::PathTraversal => f.write_str("name contains a `..` component"),
            Self::AbsolutePath => f.write_str("name is an absolute path"),
            Self::Backslash => f.write_str("name contains a backslash"),
            Self::Symlink => f.write_str("entry is a symbolic link"),
            Self::LocalHeaderOutOfRange => {
                f.write_str("local header offset is not before the central directory")
            }
            Self::LocalHeaderTruncated => {
                f.write_str("local header does not fit before the central directory")
            }
            Self::LocalHeaderMissing => f.write_str("no local header signature"),
            Self::LocalNameMismatch => {
                f.write_str("local header name differs from the central directory")
            }
            Self::LocalMethodMismatch { central, local } => write!(
                f,
                "compression method {central} in the central directory, {local} in the local header"
            ),
            Self::LocalFlagsMismatch { central, local } => write!(
                f,
                "flags {central:#06x} in the central directory, {local:#06x} in the local header"
            ),
            Self::LocalValueMismatch { field, .. } => {
                let name = match field {
                    LocalField::Crc32 => "CRC-32",
                    LocalField::CompressedSize => "compressed size",
                    LocalField::UncompressedSize => "uncompressed size",
                };
                write!(f, "local header {name} differs from the central directory")
            }
            Self::LocalZip64Invalid => f.write_str("invalid ZIP64 sizes in the local header"),
            Self::Zip64ExtraInvalid => f.write_str("invalid ZIP64 extended information"),
            Self::DataOutOfRange => f.write_str("entry extends into the central directory"),
            Self::EncryptedFlag { strong } => {
                if *strong {
                    f.write_str("encryption and strong encryption flags set")
                } else {
                    f.write_str("encryption flag set")
                }
            }
            Self::UnsupportedMethod { method } => {
                write!(f, "unsupported compression method {method}")
            }
            Self::StoredSizeMismatch => {
                f.write_str("stored entry with different compressed and uncompressed sizes")
            }
            Self::Overlap { other } => write!(f, "bytes overlap entry {other}"),
            Self::DexUnreachable { missing } => write!(
                f,
                "never loaded by ART, which stops at the missing {}",
                super::component::dex_name(*missing)
            ),
            Self::CrcMismatch { declared, actual } => {
                write!(f, "CRC-32 {actual:#010x}, declared {declared:#010x}")
            }
            Self::DataDescriptorMismatch => {
                f.write_str("data descriptor differs from the central directory")
            }
            Self::DataDescriptorUnreadable => f.write_str("data descriptor cannot be read"),
            Self::DeflateTrailingData { len } => {
                write!(f, "{len} bytes after the end of the deflate stream")
            }
        }
    }
}

/// An anomaly, attached to an entry or to the whole archive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Anomaly {
    /// What was found.
    pub kind: AnomalyKind,
    /// Index of the entry concerned, in central directory order, or `None`
    /// for the whole archive.
    pub entry: Option<usize>,
    /// The Android component whose reaction [`impact`](Self::impact)
    /// describes. For an entry, it is the component that reads that kind of
    /// entry; when another component reacts differently, the anomaly is
    /// reported once more for it. A component that scans entry names can also
    /// be named for an entry it does not read, as the native library installer
    /// is for [`AnomalyKind::NameLengthOverflow`]. `None` stands for the ZIP
    /// library shared by all components.
    pub component: Option<Component>,
}

impl Anomaly {
    pub(crate) const fn archive(kind: AnomalyKind) -> Self {
        Self {
            kind,
            entry: None,
            component: None,
        }
    }

    pub(crate) const fn archive_in(component: Component, kind: AnomalyKind) -> Self {
        Self {
            kind,
            entry: None,
            component: Some(component),
        }
    }

    pub(crate) const fn entry(index: usize, component: Component, kind: AnomalyKind) -> Self {
        Self {
            kind,
            entry: Some(index),
            component: Some(component),
        }
    }

    /// Stable identifier of the anomaly kind.
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// Known vulnerabilities that the anomaly's construction triggers, as CVE
    /// identifiers: see [`AnomalyKind::known_vulnerabilities`].
    pub const fn known_vulnerabilities(&self) -> &'static [&'static str] {
        self.kind.known_vulnerabilities()
    }

    /// What the anomaly means for an Android device, as seen by
    /// [`component`](Self::component).
    pub const fn impact(&self) -> Impact {
        self.kind.impact_in(self.component)
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] ", self.code())?;
        if let Some(index) = self.entry {
            write!(f, "entry {index}: ")?;
        }
        if let Some(component) = self.component {
            write!(f, "({}) ", component.code())?;
        }
        write!(f, "{}", self.kind)
    }
}

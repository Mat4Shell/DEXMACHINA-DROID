// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! ZIP container reader that follows Android's interpretation.
//!
//! The central directory is read the way Android's libziparchive reads it:
//! the end of central directory record closest to the end of the input, a
//! central directory walked by entry count, entry values taken from the
//! central directory, the compression method of local headers ignored, the
//! data descriptor flag taken from local headers, and no CRC check.
//!
//! Every place where Android rejects the archive, reads it differently from a
//! general-purpose ZIP reader, or meets a hostile construction is reported as
//! an [`Anomaly`] with a stable code. Reading goes on past those points
//! whenever the layout allows it, so that an analyst can see what other tools
//! would see.
//!
//! Nothing is ever written to disk: entries are returned in memory, under the
//! [`Limits`] given when the archive is opened.

mod anomaly;
mod bytes;
mod component;
mod crc32;
mod eocd;
mod error;
mod names;
mod read;

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::ops::Range;

use crate::Limits;
use bytes::{Cursor, count_occurrences, slice, u16_at, u32_at, u64_at};
use eocd::{EOCD_LEN, Eocd, Zip64Eocd};

pub use anomaly::{Anomaly, AnomalyKind, Impact, LocalField};
pub use component::Component;
pub use error::{LimitKind, ReadError, ZipError};
pub use read::EntryContent;

const LOCAL_HEADER_SIGNATURE: [u8; 4] = *b"PK\x03\x04";
const LOCAL_HEADER_LEN: u64 = 30;
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_HEADER_LEN: u64 = 46;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const ZIP64_EXTRA_ID: u16 = 0x0001;

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;

/// Names of at least this many bytes are reported as
/// [`AnomalyKind::LongName`]. It is `PATH_MAX` on Linux: Android's native
/// library installer copies entry names into a buffer of that size and skips
/// the entries whose name does not fit.
pub const LONG_NAME_LEN: usize = 4096;
/// Names with a path component longer than this many bytes are reported as
/// [`AnomalyKind::LongName`]. It is `NAME_MAX` on Linux: no file system path
/// component can be longer.
pub const LONG_NAME_COMPONENT_LEN: usize = 255;

/// Compression method: no compression.
pub const METHOD_STORED: u16 = 0;
/// Compression method: raw deflate.
pub const METHOD_DEFLATED: u16 = 8;

/// An entry of the central directory.
///
/// Values are those of the central directory, as Android uses them. Offsets
/// are absolute positions in the input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// Position of the entry in the central directory.
    pub index: usize,
    /// Raw name bytes.
    pub name: Vec<u8>,
    /// The Android component that reads this entry, from its name.
    pub component: Component,
    /// Compression method declared by the central directory.
    pub method: u16,
    /// General purpose flags of the central directory.
    pub flags: u16,
    /// General purpose flags of the local header, when it could be read.
    pub local_flags: Option<u16>,
    /// Declared CRC-32 of the uncompressed data.
    pub crc32: u32,
    /// Declared compressed size.
    pub compressed_size: u64,
    /// Declared uncompressed size.
    pub uncompressed_size: u64,
    /// Offset of the local header.
    pub local_header_offset: u64,
    /// Offset of the entry data, when the local header allows locating it.
    pub data_offset: Option<u64>,
    /// Whether the local header announces a data descriptor.
    pub has_data_descriptor: bool,
    /// Version made by, whose upper byte identifies the host system.
    pub version_made_by: u16,
    /// External file attributes.
    pub external_attributes: u32,
}

impl Entry {
    /// The name, if it is valid UTF-8.
    pub fn name_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.name).ok()
    }

    /// The name, with invalid UTF-8 sequences replaced.
    pub fn name_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }

    /// Whether the name designates a directory.
    pub fn is_dir(&self) -> bool {
        self.name.last() == Some(&b'/')
    }

    /// The Unix mode, if the entry was made on a Unix system.
    pub fn unix_mode(&self) -> Option<u32> {
        let [_, host] = self.version_made_by.to_le_bytes();
        (host == 3).then_some(self.external_attributes >> 16)
    }

    /// Whether the entry is a Unix symbolic link. Links are never followed:
    /// their content is the link target, returned as data.
    pub fn is_symlink(&self) -> bool {
        self.unix_mode()
            .is_some_and(|mode| mode & 0o170_000 == 0o120_000)
    }

    fn data_len(&self) -> u64 {
        if self.method == METHOD_STORED {
            self.uncompressed_size
        } else {
            self.compressed_size
        }
    }
}

/// Where the structures of the archive were found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Layout {
    /// Offset of the classic end of central directory record.
    pub eocd_offset: u64,
    /// Offset of the ZIP64 end of central directory record, if used.
    pub zip64_eocd_offset: Option<u64>,
    /// Offset of the central directory.
    pub central_directory_offset: u64,
    /// Size of the central directory.
    pub central_directory_size: u64,
    /// Number of entries declared by the end of central directory.
    pub declared_entries: u64,
    /// Bytes added to every declared offset to find the structures, when the
    /// archive offsets are shifted. Zero otherwise.
    pub offset_shift: u64,
    /// Bytes of the archive comment present in the input.
    pub comment: Range<u64>,
    /// The APK Signing Block, if present before the central directory.
    pub signing_block: Option<Range<u64>>,
}

/// A ZIP archive read from memory.
#[derive(Debug)]
pub struct ZipArchive<'a> {
    data: &'a [u8],
    limits: Limits,
    layout: Layout,
    entries: Vec<Entry>,
    anomalies: Vec<Anomaly>,
    produced: Cell<u64>,
}

impl<'a> ZipArchive<'a> {
    /// Reads the structure of the archive in `data`.
    ///
    /// Errors are reserved for archives whose central directory cannot be
    /// located or walked. Everything else is reported through
    /// [`anomalies`](Self::anomalies).
    pub fn parse(data: &'a [u8], limits: Limits) -> Result<Self, ZipError> {
        Parser::new(data, limits).run()
    }

    /// The entries, in central directory order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The anomalies found while reading the structure. Anomalies found while
    /// reading an entry are returned with its content.
    pub fn anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }

    /// The anomalies attached to one entry.
    pub fn entry_anomalies(&self, index: usize) -> impl Iterator<Item = &Anomaly> {
        self.anomalies
            .iter()
            .filter(move |anomaly| anomaly.entry == Some(index))
    }

    /// Where the structures of the archive were found.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The archive comment.
    pub fn comment(&self) -> &'a [u8] {
        let Range { start, end } = self.layout.comment;
        slice(self.data, start, end.saturating_sub(start)).unwrap_or_default()
    }

    /// The first entry with exactly this name.
    pub fn find(&self, name: &[u8]) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// Whether Android would open the archive: no anomaly found so far has
    /// the [`Impact::ArchiveRejected`] impact.
    pub fn android_accepts(&self) -> bool {
        !self
            .anomalies
            .iter()
            .any(|anomaly| anomaly.impact() == Impact::ArchiveRejected)
    }

    /// Number of uncompressed bytes returned by [`read`](Self::read) so far,
    /// counted against [`Limits::max_total_size`].
    pub fn total_read(&self) -> u64 {
        self.produced.get()
    }

    /// Reads the content of the entry at `index`, as Android's resource
    /// loader would: deflated entries are inflated, stored entries and
    /// entries with an unsupported method are returned as stored.
    pub fn read(&self, index: usize) -> Result<EntryContent, ReadError> {
        let entry = self.entries.get(index).ok_or(ReadError::NoSuchEntry)?;
        read::read_entry(self.data, entry, &self.limits, &self.produced)
    }
}

/// ZIP64 values found in an extra field.
#[derive(Debug, Default, Clone, Copy)]
struct Zip64Values {
    uncompressed: Option<u64>,
    compressed: Option<u64>,
    local_header_offset: Option<u64>,
}

/// Reads the ZIP64 extended information like libziparchive: the fields
/// present depend on which 32-bit values are saturated, except for a 24-byte
/// block, where all three are read, and a 28-byte block, whose disk number is
/// ignored.
fn parse_zip64_extra(
    extra: &[u8],
    uncompressed: u32,
    compressed: u32,
    local_header_offset: Option<u32>,
) -> Option<Zip64Values> {
    let len = extra.len();
    let last_header = len.checked_sub(4)?;
    if last_header == 0 {
        return None;
    }
    let mut offset: usize = 0;
    while offset < last_header {
        let block = extra.get(offset..)?;
        let mut cursor = Cursor::new(block);
        let id = cursor.u16()?;
        let mut size = usize::from(cursor.u16()?);
        offset = offset.checked_add(4)?;
        if size > len.checked_sub(offset)? {
            return None;
        }
        if id != ZIP64_EXTRA_ID {
            offset = offset.checked_add(size)?;
            continue;
        }
        if size == 28 {
            size = 24;
        }
        let complete = size == 24;
        let mut values = Zip64Values::default();
        let mut read: usize = 0;
        let body = extra.get(offset..)?;
        let mut cursor = Cursor::new(body);
        if uncompressed == u32::MAX || complete {
            values.uncompressed = Some(cursor.u64()?);
            read = read.checked_add(8)?;
        }
        if compressed == u32::MAX || complete {
            values.compressed = Some(cursor.u64()?);
            read = read.checked_add(8)?;
        }
        if local_header_offset == Some(u32::MAX) || complete {
            values.local_header_offset = Some(cursor.u64()?);
            read = read.checked_add(8)?;
        }
        if read == 0 || read != size {
            return None;
        }
        return Some(values);
    }
    None
}

/// A central directory record, as read during the first pass.
struct CentralRecord {
    name: Range<usize>,
    extra: Range<usize>,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed: u32,
    uncompressed: u32,
    local_header_offset: u64,
    version_made_by: u16,
    external_attributes: u32,
}

/// Fixed fields of a central directory header.
struct RawCentral {
    version_made_by: u16,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed: u32,
    uncompressed: u32,
    name_len: u16,
    extra_len: u16,
    comment_len: u16,
    external_attributes: u32,
    local_header_offset: u32,
}

impl RawCentral {
    fn parse(header: &[u8]) -> Option<Self> {
        let mut cursor = Cursor::new(header.get(4..)?);
        let version_made_by = cursor.u16()?;
        let _version_needed = cursor.u16()?;
        let flags = cursor.u16()?;
        let method = cursor.u16()?;
        let _time = cursor.u16()?;
        let _date = cursor.u16()?;
        let crc32 = cursor.u32()?;
        let compressed = cursor.u32()?;
        let uncompressed = cursor.u32()?;
        let name_len = cursor.u16()?;
        let extra_len = cursor.u16()?;
        let comment_len = cursor.u16()?;
        let _disk = cursor.u16()?;
        let _internal_attributes = cursor.u16()?;
        let external_attributes = cursor.u32()?;
        let local_header_offset = cursor.u32()?;
        Some(Self {
            version_made_by,
            flags,
            method,
            crc32,
            compressed,
            uncompressed,
            name_len,
            extra_len,
            comment_len,
            external_attributes,
            local_header_offset,
        })
    }
}

/// Fixed fields of a local file header.
struct RawLocal {
    flags: u16,
    method: u16,
    crc32: u32,
    compressed: u32,
    uncompressed: u32,
    name_len: u16,
    extra_len: u16,
}

impl RawLocal {
    fn parse(header: &[u8]) -> Option<Self> {
        let mut cursor = Cursor::new(header.get(4..)?);
        let _version_needed = cursor.u16()?;
        let flags = cursor.u16()?;
        let method = cursor.u16()?;
        let _time = cursor.u16()?;
        let _date = cursor.u16()?;
        let crc32 = cursor.u32()?;
        let compressed = cursor.u32()?;
        let uncompressed = cursor.u32()?;
        let name_len = cursor.u16()?;
        let extra_len = cursor.u16()?;
        Some(Self {
            flags,
            method,
            crc32,
            compressed,
            uncompressed,
            name_len,
            extra_len,
        })
    }
}

/// The central directory location, as Android computes it.
struct Directory {
    offset: u64,
    size: u64,
    entries: u64,
    zip64: Option<Zip64Eocd>,
}

struct Parser<'a> {
    data: &'a [u8],
    limits: Limits,
    anomalies: Vec<Anomaly>,
    /// Component of each entry read so far, by index.
    components: Vec<Component>,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8], limits: Limits) -> Self {
        Self {
            data,
            limits,
            anomalies: Vec::new(),
            components: Vec::new(),
        }
    }

    fn archive(&mut self, kind: AnomalyKind) {
        self.anomalies.push(Anomaly::archive(kind));
    }

    fn entry(&mut self, index: usize, kind: AnomalyKind) {
        let component = self
            .components
            .get(index)
            .copied()
            .unwrap_or(Component::Resources);
        self.anomalies.push(Anomaly::entry(index, component, kind));
    }

    /// Reports an anomaly for the component that reads the entry, and again
    /// for the JAR signature verifier, which digests every entry and reads
    /// its content differently.
    fn entry_and_jar_signature(&mut self, index: usize, kind: AnomalyKind) {
        let component = self.components.get(index).copied();
        self.entry(index, kind.clone());
        if component != Some(Component::JarSignature) {
            self.anomalies
                .push(Anomaly::entry(index, Component::JarSignature, kind));
        }
    }

    fn input_len(&self) -> u64 {
        u64::try_from(self.data.len()).unwrap_or(u64::MAX)
    }

    fn run(mut self) -> Result<ZipArchive<'a>, ZipError> {
        let located = eocd::locate(self.data)?;
        let eocd = located.eocd;
        self.check_eocd(&eocd, located.other_candidates);
        let comment_start = eocd.offset.saturating_add(EOCD_LEN);
        let comment = comment_start..eocd.declared_end().min(self.input_len());

        let directory = self.directory(&eocd)?;
        if directory.entries > self.limits.max_entries {
            return Err(ZipError::LimitExceeded {
                limit: LimitKind::Entries,
                value: directory.entries,
                max: self.limits.max_entries,
            });
        }
        if directory.size > self.limits.max_central_directory_size {
            return Err(ZipError::LimitExceeded {
                limit: LimitKind::CentralDirectorySize,
                value: directory.size,
                max: self.limits.max_central_directory_size,
            });
        }
        if directory.entries == 0 {
            self.archive(AnomalyKind::EmptyArchive);
        }

        let shift = self.offset_shift(&eocd, &directory);
        let cd_offset = directory
            .offset
            .checked_add(shift)
            .ok_or(ZipError::CentralDirectoryOutOfBounds)?;
        let cd = slice(self.data, cd_offset, directory.size)
            .ok_or(ZipError::CentralDirectoryOutOfBounds)?;

        let (records, consumed) = self.central_records(cd, cd_offset, &directory, shift)?;
        self.check_central_tail(cd, consumed);
        let next_structure = directory.zip64.map_or(eocd.offset, |zip64| zip64.offset);
        let cd_end = cd_offset.saturating_add(directory.size);
        if cd_end < next_structure {
            self.anomalies.push(Anomaly::archive_in(
                Component::SigningBlock,
                AnomalyKind::CentralDirectoryGap {
                    offset: cd_end,
                    len: next_structure.saturating_sub(cd_end),
                },
            ));
        }

        let mut entries = Vec::with_capacity(records.len());
        for (index, record) in records.iter().enumerate() {
            entries.push(self.entry_from_record(index, record, cd, cd_offset));
        }
        self.check_names(&entries);
        if directory.entries > 0 {
            self.check_prefix(&entries, cd_offset);
        }
        let signing_block = self.signing_block(cd_offset);
        self.check_coverage(&entries, signing_block.as_ref(), cd_offset);

        Ok(ZipArchive {
            data: self.data,
            limits: self.limits,
            layout: Layout {
                eocd_offset: eocd.offset,
                zip64_eocd_offset: directory.zip64.map(|zip64| zip64.offset),
                central_directory_offset: cd_offset,
                central_directory_size: directory.size,
                declared_entries: directory.entries,
                offset_shift: shift,
                comment,
                signing_block,
            },
            entries,
            anomalies: self.anomalies,
            produced: Cell::new(0),
        })
    }

    fn check_eocd(&mut self, eocd: &Eocd, other_candidates: Vec<u64>) {
        let declared_end = eocd.declared_end();
        let actual_len = self.input_len();
        if declared_end != actual_len {
            self.archive(AnomalyKind::EocdLengthMismatch {
                declared_end,
                actual_len,
            });
        }
        if !other_candidates.is_empty() {
            self.archive(AnomalyKind::EocdMultipleCandidates {
                offsets: other_candidates,
            });
        }
        if eocd.comment_len > 0 {
            self.archive(AnomalyKind::EocdComment {
                len: u64::from(eocd.comment_len),
            });
        }
    }

    /// Finds the central directory from the classic record, or from the ZIP64
    /// record when the classic one carries a ZIP64 marker.
    fn directory(&mut self, eocd: &Eocd) -> Result<Directory, ZipError> {
        let zip64 = if eocd.has_zip64_marker() {
            match eocd::locate_zip64(self.data, eocd.offset) {
                Some(zip64) => Some(zip64),
                None => {
                    if eocd::has_zip64_locator(self.data, eocd.offset) {
                        return Err(ZipError::Zip64Invalid);
                    }
                    self.archive(AnomalyKind::Zip64LocatorMissing);
                    None
                }
            }
        } else {
            None
        };

        let directory = match zip64 {
            Some(zip64) => {
                self.anomalies.push(Anomaly::archive_in(
                    Component::SigningBlock,
                    AnomalyKind::Zip64,
                ));
                let mismatch = (eocd.entries_total != u16::MAX
                    && u64::from(eocd.entries_total) != zip64.entries_total)
                    || (eocd.cd_size != u32::MAX && u64::from(eocd.cd_size) != zip64.cd_size)
                    || (eocd.cd_offset != u32::MAX && u64::from(eocd.cd_offset) != zip64.cd_offset);
                if mismatch {
                    self.archive(AnomalyKind::Zip64EocdMismatch);
                }
                if zip64.disk != 0
                    || zip64.cd_disk != 0
                    || zip64.entries_on_disk != zip64.entries_total
                {
                    self.archive(AnomalyKind::EocdMultiDisk {
                        disk: zip64.disk,
                        cd_disk: zip64.cd_disk,
                        entries_on_disk: zip64.entries_on_disk,
                        entries_total: zip64.entries_total,
                    });
                }
                Directory {
                    offset: zip64.cd_offset,
                    size: zip64.cd_size,
                    entries: zip64.entries_total,
                    zip64: Some(zip64),
                }
            }
            None => {
                let offset = u64::from(eocd.cd_offset);
                let size = u64::from(eocd.cd_size);
                if offset.saturating_add(size) > eocd.offset {
                    return Err(ZipError::CentralDirectoryOutOfBounds);
                }
                if eocd.disk != 0 || eocd.cd_disk != 0 || eocd.entries_on_disk != eocd.entries_total
                {
                    self.archive(AnomalyKind::EocdMultiDisk {
                        disk: u32::from(eocd.disk),
                        cd_disk: u32::from(eocd.cd_disk),
                        entries_on_disk: u64::from(eocd.entries_on_disk),
                        entries_total: u64::from(eocd.entries_total),
                    });
                }
                Directory {
                    offset,
                    size,
                    entries: u64::from(eocd.entries_total),
                    zip64: None,
                }
            }
        };
        Ok(directory)
    }

    /// Detects an archive whose offsets were not adjusted after data was
    /// prepended: the central directory is not at its declared offset, but
    /// immediately before the end record. Android does not compensate; the
    /// shift is applied here so that reading can go on.
    fn offset_shift(&mut self, eocd: &Eocd, directory: &Directory) -> u64 {
        if directory.entries == 0 || directory.zip64.is_some() {
            return 0;
        }
        if u32_at(self.data, directory.offset) == Some(CENTRAL_HEADER_SIGNATURE) {
            return 0;
        }
        let Some(actual) = eocd.offset.checked_sub(directory.size) else {
            return 0;
        };
        if actual <= directory.offset || u32_at(self.data, actual) != Some(CENTRAL_HEADER_SIGNATURE)
        {
            return 0;
        }
        let delta = actual.saturating_sub(directory.offset);
        self.archive(AnomalyKind::OffsetsShifted { delta });
        delta
    }

    /// First pass over the central directory, with the checks libziparchive
    /// makes when it opens an archive. Returns the records and the number of
    /// central directory bytes they use.
    fn central_records(
        &mut self,
        cd: &[u8],
        cd_offset: u64,
        directory: &Directory,
        shift: u64,
    ) -> Result<(Vec<CentralRecord>, u64), ZipError> {
        let cd_len = directory.size;
        let capacity = directory
            .entries
            .min(cd_len.checked_div(CENTRAL_HEADER_LEN).unwrap_or_default());
        let mut records = Vec::with_capacity(usize::try_from(capacity).unwrap_or_default());
        let mut pos: u64 = 0;
        for entry in 0..directory.entries {
            let truncated = ZipError::CentralDirectoryTruncated { entry };
            let header = slice(cd, pos, CENTRAL_HEADER_LEN).ok_or(truncated)?;
            if u32_at(header, 0) != Some(CENTRAL_HEADER_SIGNATURE) {
                return Err(ZipError::BadCentralDirectorySignature { entry });
            }
            let RawCentral {
                version_made_by,
                flags,
                method,
                crc32,
                compressed,
                uncompressed,
                name_len,
                extra_len,
                comment_len,
                external_attributes,
                local_header_offset: local_offset32,
            } = RawCentral::parse(header).ok_or(truncated)?;

            let name_start = pos.checked_add(CENTRAL_HEADER_LEN).ok_or(truncated)?;
            let name_end = name_start
                .checked_add(u64::from(name_len))
                .ok_or(truncated)?;
            let extra_end = name_end
                .checked_add(u64::from(extra_len))
                .ok_or(truncated)?;
            if u64::from(name_len) >= cd_len || name_end > cd_len {
                return Err(truncated);
            }
            if u64::from(extra_len) >= cd_len || extra_end > cd_len {
                return Err(truncated);
            }
            let name = to_usize_range(name_start, name_end).ok_or(truncated)?;
            let extra = to_usize_range(name_end, extra_end).ok_or(truncated)?;

            let mut local_header_offset = u64::from(local_offset32);
            if local_offset32 == u32::MAX {
                let extra_bytes = cd.get(extra.clone()).unwrap_or_default();
                local_header_offset =
                    parse_zip64_extra(extra_bytes, uncompressed, compressed, Some(local_offset32))
                        .and_then(|values| values.local_header_offset)
                        .ok_or(ZipError::Zip64ExtraInvalid { entry })?;
            }
            let local_header_offset = local_header_offset.saturating_add(shift);

            let index = usize::try_from(entry).unwrap_or(usize::MAX);
            let name_bytes = cd.get(name.clone()).unwrap_or_default();
            self.components.push(Component::for_entry(name_bytes));
            if local_header_offset >= cd_offset {
                self.entry(index, AnomalyKind::LocalHeaderOutOfRange);
            }
            if !names::is_valid_for_android(name_bytes) {
                self.entry(index, AnomalyKind::InvalidName);
            }

            pos = extra_end
                .checked_add(u64::from(comment_len))
                .ok_or(truncated)?;
            if pos > cd_len {
                return Err(truncated);
            }
            records.push(CentralRecord {
                name,
                extra,
                method,
                flags,
                crc32,
                compressed,
                uncompressed,
                local_header_offset,
                version_made_by,
                external_attributes,
            });
        }
        Ok((records, pos))
    }

    /// Looks at what follows the declared entries in the central directory.
    fn check_central_tail(&mut self, cd: &[u8], consumed: u64) {
        let cd_len = u64::try_from(cd.len()).unwrap_or(u64::MAX);
        let mut pos = consumed;
        let mut hidden: u64 = 0;
        while let Some(header) = slice(cd, pos, CENTRAL_HEADER_LEN) {
            if u32_at(header, 0) != Some(CENTRAL_HEADER_SIGNATURE) {
                break;
            }
            let lengths = [28u64, 30, 32].map(|at| u16_at(header, at).map(u64::from));
            let [Some(name), Some(extra), Some(comment)] = lengths else {
                break;
            };
            let Some(end) = pos
                .checked_add(CENTRAL_HEADER_LEN)
                .and_then(|v| v.checked_add(name))
                .and_then(|v| v.checked_add(extra))
                .and_then(|v| v.checked_add(comment))
            else {
                break;
            };
            if end > cd_len {
                break;
            }
            hidden = hidden.saturating_add(1);
            pos = end;
        }
        if hidden > 0 {
            self.archive(AnomalyKind::HiddenCentralRecords { count: hidden });
        }
        if pos < cd_len {
            self.archive(AnomalyKind::CentralDirectoryTrailingBytes {
                len: cd_len.saturating_sub(pos),
            });
        }
    }

    /// Builds an entry and checks its local header, like libziparchive's
    /// `FindEntry` does on each access.
    fn entry_from_record(
        &mut self,
        index: usize,
        record: &CentralRecord,
        cd: &[u8],
        cd_offset: u64,
    ) -> Entry {
        let name = cd.get(record.name.clone()).unwrap_or_default().to_vec();
        let mut entry = Entry {
            index,
            component: Component::for_entry(&name),
            name,
            method: record.method,
            flags: record.flags,
            local_flags: None,
            crc32: record.crc32,
            compressed_size: u64::from(record.compressed),
            uncompressed_size: u64::from(record.uncompressed),
            local_header_offset: record.local_header_offset,
            data_offset: None,
            has_data_descriptor: false,
            version_made_by: record.version_made_by,
            external_attributes: record.external_attributes,
        };

        if record.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 {
            self.entry(
                index,
                AnomalyKind::EncryptedFlag {
                    strong: record.flags & FLAG_STRONG_ENCRYPTION != 0,
                },
            );
        }
        if record.method != METHOD_STORED && record.method != METHOD_DEFLATED {
            self.entry_and_jar_signature(
                index,
                AnomalyKind::UnsupportedMethod {
                    method: record.method,
                },
            );
        }
        if entry.is_symlink() {
            self.entry(index, AnomalyKind::Symlink);
        }

        let needs_zip64 = record.uncompressed == u32::MAX || record.compressed == u32::MAX;
        if needs_zip64 {
            let extra = cd.get(record.extra.clone()).unwrap_or_default();
            match parse_zip64_extra(extra, record.uncompressed, record.compressed, None) {
                Some(values) => {
                    entry.uncompressed_size =
                        values.uncompressed.unwrap_or(entry.uncompressed_size);
                    entry.compressed_size = values.compressed.unwrap_or(entry.compressed_size);
                }
                None => {
                    self.entry(index, AnomalyKind::Zip64ExtraInvalid);
                    return entry;
                }
            }
        }
        if entry.method == METHOD_STORED && entry.compressed_size != entry.uncompressed_size {
            self.entry(index, AnomalyKind::StoredSizeMismatch);
        }

        if entry.local_header_offset >= cd_offset {
            return entry;
        }
        self.check_local_header(&mut entry, cd_offset);
        entry
    }

    fn check_local_header(&mut self, entry: &mut Entry, cd_offset: u64) {
        let index = entry.index;
        let lfh = entry.local_header_offset;
        if lfh.saturating_add(LOCAL_HEADER_LEN) >= cd_offset {
            self.entry(index, AnomalyKind::LocalHeaderTruncated);
            return;
        }
        let Some(header) = slice(self.data, lfh, LOCAL_HEADER_LEN) else {
            self.entry(index, AnomalyKind::LocalHeaderTruncated);
            return;
        };
        if header.get(..4) != Some(&LOCAL_HEADER_SIGNATURE[..]) {
            self.entry(index, AnomalyKind::LocalHeaderMissing);
            return;
        }
        let Some(RawLocal {
            flags,
            method,
            crc32,
            compressed,
            uncompressed,
            name_len,
            extra_len,
        }) = RawLocal::parse(header)
        else {
            self.entry(index, AnomalyKind::LocalHeaderTruncated);
            return;
        };
        entry.local_flags = Some(flags);

        let name_start = lfh.saturating_add(LOCAL_HEADER_LEN);
        let name_end = name_start.saturating_add(u64::from(name_len));
        let local_name = slice(self.data, name_start, u64::from(name_len));
        if local_name != Some(entry.name.as_slice()) {
            self.entry(index, AnomalyKind::LocalNameMismatch);
        }
        if name_end > cd_offset {
            self.entry(index, AnomalyKind::DataOutOfRange);
            return;
        }
        let extra_end = name_end.saturating_add(u64::from(extra_len));
        if extra_end > cd_offset {
            self.entry(index, AnomalyKind::DataOutOfRange);
            return;
        }

        let mut local_compressed = u64::from(compressed);
        let mut local_uncompressed = u64::from(uncompressed);
        if compressed == u32::MAX || uncompressed == u32::MAX {
            let values = if compressed == u32::MAX && uncompressed == u32::MAX {
                slice(self.data, name_end, u64::from(extra_len))
                    .and_then(|extra| parse_zip64_extra(extra, uncompressed, compressed, None))
            } else {
                None
            };
            match values {
                Some(Zip64Values {
                    uncompressed: Some(u),
                    compressed: Some(c),
                    ..
                }) => {
                    local_uncompressed = u;
                    local_compressed = c;
                }
                _ => {
                    self.entry(index, AnomalyKind::LocalZip64Invalid);
                    return;
                }
            }
        }

        if flags != entry.flags {
            self.entry(
                index,
                AnomalyKind::LocalFlagsMismatch {
                    central: entry.flags,
                    local: flags,
                },
            );
            if flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0
                && entry.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) == 0
            {
                self.entry(
                    index,
                    AnomalyKind::EncryptedFlag {
                        strong: flags & FLAG_STRONG_ENCRYPTION != 0,
                    },
                );
            }
        }
        if method != entry.method {
            self.entry(
                index,
                AnomalyKind::LocalMethodMismatch {
                    central: entry.method,
                    local: method,
                },
            );
        }

        let data_descriptor = flags & FLAG_DATA_DESCRIPTOR != 0;
        entry.has_data_descriptor = data_descriptor;
        let comparisons = [
            (LocalField::Crc32, u64::from(crc32), u64::from(entry.crc32)),
            (
                LocalField::CompressedSize,
                local_compressed,
                entry.compressed_size,
            ),
            (
                LocalField::UncompressedSize,
                local_uncompressed,
                entry.uncompressed_size,
            ),
        ];
        for (field, local, central) in comparisons {
            // With a data descriptor, writers leave the local values at zero.
            let differs = local != central && !(data_descriptor && local == 0);
            if differs {
                self.entry(
                    index,
                    AnomalyKind::LocalValueMismatch {
                        field,
                        data_descriptor,
                    },
                );
            }
        }

        let data_offset = extra_end;
        let room = cd_offset.saturating_sub(data_offset);
        if entry.compressed_size > room
            || (entry.method == METHOD_STORED && entry.uncompressed_size > room)
        {
            self.entry(index, AnomalyKind::DataOutOfRange);
        }
        entry.data_offset = Some(data_offset);
    }

    fn check_names(&mut self, entries: &[Entry]) {
        let mut exact: HashMap<&[u8], usize> = HashMap::with_capacity(entries.len());
        let mut folded: HashMap<Vec<u8>, usize> = HashMap::with_capacity(entries.len());
        for entry in entries {
            let index = entry.index;
            let name = entry.name.as_slice();
            if let Some(&first) = exact.get(name) {
                self.entry(index, AnomalyKind::DuplicateName { first });
            } else {
                exact.insert(name, index);
                let lower = name.to_ascii_lowercase();
                if let Some(&first) = folded.get(&lower) {
                    self.entry(index, AnomalyKind::CaseCollision { first });
                } else {
                    folded.insert(lower, index);
                }
            }
            if name.is_empty() {
                self.entry(index, AnomalyKind::EmptyName);
            }
            let longest_component = names::longest_component(name);
            if name.len() >= LONG_NAME_LEN || longest_component > LONG_NAME_COMPONENT_LEN {
                self.entry(
                    index,
                    AnomalyKind::LongName {
                        len: u64::try_from(name.len()).unwrap_or(u64::MAX),
                        longest_component: u64::try_from(longest_component).unwrap_or(u64::MAX),
                    },
                );
            }
            if names::is_valid_for_android(name) && std::str::from_utf8(name).is_err() {
                self.entry(index, AnomalyKind::NameNotStrictUtf8);
            }
            if names::has_parent_component(name) {
                self.entry(index, AnomalyKind::PathTraversal);
            }
            if names::is_absolute(name) {
                self.entry(index, AnomalyKind::AbsolutePath);
            }
            if name.contains(&b'\\') {
                self.entry(index, AnomalyKind::Backslash);
            }
        }
    }

    /// Android requires a local header signature at offset zero.
    fn check_prefix(&mut self, entries: &[Entry], cd_offset: u64) {
        if self.data.get(..4) == Some(&LOCAL_HEADER_SIGNATURE[..]) {
            return;
        }
        let first = entries
            .iter()
            .map(|entry| entry.local_header_offset)
            .min()
            .unwrap_or(cd_offset)
            .min(cd_offset);
        self.archive(AnomalyKind::PrefixData { len: first });
    }

    /// Locates the APK Signing Block, which ends right before the central
    /// directory with a size field and a magic value.
    fn signing_block(&mut self, cd_offset: u64) -> Option<Range<u64>> {
        let footer = cd_offset.checked_sub(24)?;
        if slice(self.data, footer.checked_add(8)?, 16) != Some(&SIGNING_BLOCK_MAGIC[..]) {
            return None;
        }
        let block = (|| {
            let size = u64_at(self.data, footer)?;
            let start = cd_offset.checked_sub(size.checked_add(8)?)?;
            (size >= 24 && u64_at(self.data, start)? == size).then_some(start..cd_offset)
        })();
        if block.is_none() {
            self.archive(AnomalyKind::SigningBlockMalformed);
        }
        block
    }

    /// Checks that the bytes before the central directory belong to exactly
    /// one entry each, or to the APK Signing Block.
    fn check_coverage(
        &mut self,
        entries: &[Entry],
        signing_block: Option<&Range<u64>>,
        cd_offset: u64,
    ) {
        let mut regions: Vec<(u64, u64, Option<usize>)> = entries
            .iter()
            .filter_map(|entry| {
                let data_offset = entry.data_offset?;
                let data_end = data_offset.saturating_add(entry.data_len());
                let end = data_end.saturating_add(self.data_descriptor_len(entry, data_end));
                Some((
                    entry.local_header_offset,
                    end.min(cd_offset),
                    Some(entry.index),
                ))
            })
            .collect();
        if let Some(block) = signing_block {
            regions.push((block.start, block.end, None));
        }
        regions.sort_unstable();

        let prefix_reported = self
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly.kind, AnomalyKind::PrefixData { .. }));
        let mut cursor: u64 = 0;
        let mut furthest: Option<usize> = None;
        let mut gaps = Vec::new();
        for (start, end, index) in regions {
            if start > cursor {
                gaps.push(cursor..start);
            } else if start < cursor
                && let (Some(index), Some(other)) = (index, furthest)
            {
                self.entry(index, AnomalyKind::Overlap { other });
            }
            if end > cursor {
                cursor = end;
                furthest = index;
            }
        }
        if cd_offset > cursor {
            gaps.push(cursor..cd_offset);
        }

        for gap in gaps {
            let len = gap.end.saturating_sub(gap.start);
            let bytes = slice(self.data, gap.start, len).unwrap_or_default();
            if !(gap.start == 0 && prefix_reported) {
                self.archive(AnomalyKind::UnaccountedData {
                    offset: gap.start,
                    len,
                    zero_filled: bytes.iter().all(|&b| b == 0),
                });
            }
            let count = count_occurrences(bytes, &LOCAL_HEADER_SIGNATURE);
            if count > 0 {
                self.archive(AnomalyKind::HiddenLocalHeaders {
                    offset: gap.start,
                    count,
                });
            }
        }
    }

    /// Length of the data descriptor that follows the entry data, sized the
    /// way libziparchive reads it.
    fn data_descriptor_len(&self, entry: &Entry, data_end: u64) -> u64 {
        if !entry.has_data_descriptor {
            return 0;
        }
        let signature = if u32_at(self.data, data_end) == Some(DATA_DESCRIPTOR_SIGNATURE) {
            4
        } else {
            0
        };
        let sizes: u64 = if read::is_zip64_sized(entry) { 16 } else { 8 };
        sizes.saturating_add(4).saturating_add(signature)
    }
}

fn to_usize_range(start: u64, end: u64) -> Option<Range<usize>> {
    Some(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

#[cfg(test)]
mod tests {
    use super::parse_zip64_extra;

    fn block(id: u16, body: &[u8]) -> Vec<u8> {
        let mut out = id.to_le_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn zip64_extra_reads_only_saturated_fields() {
        let extra = block(1, &7u64.to_le_bytes());
        let values = parse_zip64_extra(&extra, u32::MAX, 10, Some(0)).unwrap();
        assert_eq!(values.uncompressed, Some(7));
        assert_eq!(values.compressed, None);
        assert!(parse_zip64_extra(&extra, 10, 10, Some(0)).is_none());
    }

    #[test]
    fn zip64_extra_reads_complete_blocks() {
        let mut body = Vec::new();
        for value in [1u64, 2, 3] {
            body.extend_from_slice(&value.to_le_bytes());
        }
        let mut extra = block(0xCAFE, b"xy");
        extra.extend(block(1, &body));
        let values = parse_zip64_extra(&extra, 0, 0, None).unwrap();
        assert_eq!(
            (
                values.uncompressed,
                values.compressed,
                values.local_header_offset
            ),
            (Some(1), Some(2), Some(3))
        );
    }

    #[test]
    fn zip64_extra_rejects_bad_sizes() {
        assert!(parse_zip64_extra(&[], u32::MAX, 0, None).is_none());
        assert!(parse_zip64_extra(&[1, 0, 0, 0], u32::MAX, 0, None).is_none());
        let extra = block(1, &[0; 12]);
        assert!(parse_zip64_extra(&extra, u32::MAX, 0, None).is_none());
        let mut truncated = block(1, &[0; 8]);
        truncated.truncate(10);
        assert!(parse_zip64_extra(&truncated, u32::MAX, 0, None).is_none());
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Builds ZIP archives byte by byte, so that every field can be set to a
//! hostile value. No test archive is stored in the repository.

#![cfg(test)]
#![allow(dead_code)]

pub mod seeds;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATED: u16 = 8;
pub const FLAG_ENCRYPTED: u16 = 0x0001;
pub const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 9)
}

fn u16le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u32le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn len16(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).unwrap()
}

fn len32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap()
}

/// Values of the local header that differ from the central directory.
#[derive(Clone, Default)]
pub struct LocalOverrides {
    pub name: Option<Vec<u8>>,
    pub method: Option<u16>,
    pub flags: Option<u16>,
    pub crc32: Option<u32>,
    pub compressed_size: Option<u32>,
    pub uncompressed_size: Option<u32>,
    pub extra: Vec<u8>,
}

#[derive(Clone)]
pub struct EntrySpec {
    pub name: Vec<u8>,
    /// Bytes stored after the local header.
    pub payload: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub version_made_by: u16,
    pub external_attributes: u32,
    pub central_extra: Vec<u8>,
    pub local: LocalOverrides,
    /// Bytes written right after the payload.
    pub data_descriptor: Vec<u8>,
    /// Overrides the local header offset written in the central directory.
    pub local_header_offset: Option<u32>,
    /// Writes the central directory record only, without local header.
    pub central_only: bool,
}

impl EntrySpec {
    pub fn stored(name: &str, content: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            payload: content.to_vec(),
            method: METHOD_STORED,
            flags: 0,
            crc32: crc32(content),
            compressed_size: len32(content),
            uncompressed_size: len32(content),
            version_made_by: 0x0314,
            external_attributes: 0o100_644 << 16,
            central_extra: Vec::new(),
            local: LocalOverrides::default(),
            data_descriptor: Vec::new(),
            local_header_offset: None,
            central_only: false,
        }
    }

    pub fn deflated(name: &str, content: &[u8]) -> Self {
        let payload = deflate(content);
        Self {
            compressed_size: len32(&payload),
            payload,
            method: METHOD_DEFLATED,
            ..Self::stored(name, content)
        }
    }

    pub fn with_name_bytes(mut self, name: &[u8]) -> Self {
        self.name = name.to_vec();
        self
    }

    /// Moves CRC and sizes to a data descriptor, as streaming writers do.
    pub fn with_data_descriptor(mut self, signature: bool) -> Self {
        self.flags |= FLAG_DATA_DESCRIPTOR;
        self.local.crc32 = Some(0);
        self.local.compressed_size = Some(0);
        self.local.uncompressed_size = Some(0);
        let mut dd = Vec::new();
        if signature {
            u32le(&mut dd, 0x0807_4b50);
        }
        u32le(&mut dd, self.crc32);
        u32le(&mut dd, self.compressed_size);
        u32le(&mut dd, self.uncompressed_size);
        self.data_descriptor = dd;
        self
    }
}

/// Where the archive comment comes from.
#[derive(Clone, Default)]
pub struct EocdOverrides {
    pub disk: Option<u16>,
    pub entries_on_disk: Option<u16>,
    pub entries_total: Option<u16>,
    pub cd_size: Option<u32>,
    pub cd_offset: Option<u32>,
    pub comment_len: Option<u16>,
}

#[derive(Clone, Default)]
pub struct ZipBuilder {
    pub entries: Vec<EntrySpec>,
    /// Bytes written before the first local header.
    pub prefix: Vec<u8>,
    /// Whether offsets account for the prefix. When false, the archive is
    /// built as if the prefix had been prepended to a finished archive.
    pub offsets_include_prefix: bool,
    /// Bytes written between the last entry and the central directory.
    pub before_central_directory: Vec<u8>,
    /// Bytes written at the end of the central directory, counted in its
    /// size but not as an entry.
    pub central_directory_tail: Vec<u8>,
    /// Bytes written between the central directory and the end record.
    pub after_central_directory: Vec<u8>,
    pub comment: Vec<u8>,
    pub eocd: EocdOverrides,
    /// Bytes written after the end record and its comment.
    pub trailer: Vec<u8>,
}

impl ZipBuilder {
    pub fn new() -> Self {
        Self {
            offsets_include_prefix: true,
            ..Self::default()
        }
    }

    pub fn entry(mut self, entry: EntrySpec) -> Self {
        self.entries.push(entry);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = self.prefix.clone();
        let base = if self.offsets_include_prefix {
            0
        } else {
            len32(&self.prefix)
        };
        let mut offsets = Vec::new();
        for entry in &self.entries {
            offsets.push(len32(&out).checked_sub(base).unwrap());
            if entry.central_only {
                continue;
            }
            let local = &entry.local;
            let name = local.name.as_deref().unwrap_or(&entry.name);
            u32le(&mut out, 0x0403_4b50);
            u16le(&mut out, 20);
            u16le(&mut out, local.flags.unwrap_or(entry.flags));
            u16le(&mut out, local.method.unwrap_or(entry.method));
            u16le(&mut out, 0);
            u16le(&mut out, 0x21);
            u32le(&mut out, local.crc32.unwrap_or(entry.crc32));
            u32le(
                &mut out,
                local.compressed_size.unwrap_or(entry.compressed_size),
            );
            u32le(
                &mut out,
                local.uncompressed_size.unwrap_or(entry.uncompressed_size),
            );
            u16le(&mut out, len16(name));
            u16le(&mut out, len16(&local.extra));
            out.extend_from_slice(name);
            out.extend_from_slice(&local.extra);
            out.extend_from_slice(&entry.payload);
            out.extend_from_slice(&entry.data_descriptor);
        }
        out.extend_from_slice(&self.before_central_directory);

        let cd_start = len32(&out);
        for (entry, offset) in self.entries.iter().zip(&offsets) {
            u32le(&mut out, 0x0201_4b50);
            u16le(&mut out, entry.version_made_by);
            u16le(&mut out, 20);
            u16le(&mut out, entry.flags);
            u16le(&mut out, entry.method);
            u16le(&mut out, 0);
            u16le(&mut out, 0x21);
            u32le(&mut out, entry.crc32);
            u32le(&mut out, entry.compressed_size);
            u32le(&mut out, entry.uncompressed_size);
            u16le(&mut out, len16(&entry.name));
            u16le(&mut out, len16(&entry.central_extra));
            u16le(&mut out, 0);
            u16le(&mut out, 0);
            u16le(&mut out, 0);
            u32le(&mut out, entry.external_attributes);
            u32le(&mut out, entry.local_header_offset.unwrap_or(*offset));
            out.extend_from_slice(&entry.name);
            out.extend_from_slice(&entry.central_extra);
        }
        out.extend_from_slice(&self.central_directory_tail);
        let cd_size = len32(&out).checked_sub(cd_start).unwrap();
        out.extend_from_slice(&self.after_central_directory);

        let count = u16::try_from(self.entries.len()).unwrap();
        let eocd = &self.eocd;
        u32le(&mut out, 0x0605_4b50);
        u16le(&mut out, eocd.disk.unwrap_or(0));
        u16le(&mut out, 0);
        u16le(&mut out, eocd.entries_on_disk.unwrap_or(count));
        u16le(&mut out, eocd.entries_total.unwrap_or(count));
        u32le(&mut out, eocd.cd_size.unwrap_or(cd_size));
        u32le(
            &mut out,
            eocd.cd_offset
                .unwrap_or(cd_start.checked_sub(base).unwrap()),
        );
        u16le(&mut out, eocd.comment_len.unwrap_or(len16(&self.comment)));
        out.extend_from_slice(&self.comment);
        out.extend_from_slice(&self.trailer);
        out
    }
}

/// A small valid archive: a stored manifest, a deflated DEX, and two entries
/// with data descriptors, one of them empty.
pub fn sample() -> ZipBuilder {
    ZipBuilder::new()
        .entry(EntrySpec::stored("AndroidManifest.xml", b"<manifest/>"))
        .entry(EntrySpec::deflated(
            "classes.dex",
            &b"dex\n035\0".repeat(200),
        ))
        .entry(
            EntrySpec::deflated("res/raw/data.txt", b"hello hello hello")
                .with_data_descriptor(true),
        )
        .entry(EntrySpec::stored("assets/empty", b"").with_data_descriptor(false))
}

/// A central directory record for an entry that has no local header, to be
/// appended past the declared entry count.
pub fn bare_central_record(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    u32le(&mut out, 0x0201_4b50);
    out.extend_from_slice(&[0; 24]);
    u16le(&mut out, len16(name));
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(name);
    out
}

/// A minimal APK Signing Block with no signer.
pub fn signing_block() -> Vec<u8> {
    let mut pairs = Vec::new();
    pairs.extend_from_slice(&12u64.to_le_bytes());
    u32le(&mut pairs, 0x4242_4242);
    pairs.extend_from_slice(&[0; 8]);
    let size = u64::try_from(pairs.len().checked_add(24).unwrap()).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&pairs);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(b"APK Sig Block 42");
    out
}

/// Turns an archive without comment into a ZIP64 archive: a ZIP64 end of
/// central directory record and its locator are inserted before the classic
/// record, whose central directory fields are set to their ZIP64 markers.
pub fn into_zip64(archive: &[u8]) -> Vec<u8> {
    let eocd_offset = archive.len().checked_sub(22).unwrap();
    let eocd = &archive[eocd_offset..];
    let entries = u64::from(u16::from_le_bytes([eocd[10], eocd[11]]));
    let cd_size = u64::from(u32::from_le_bytes(eocd[12..16].try_into().unwrap()));
    let cd_offset = u64::from(u32::from_le_bytes(eocd[16..20].try_into().unwrap()));

    let mut out = archive[..eocd_offset].to_vec();
    let record_offset = u64::try_from(out.len()).unwrap();
    u32le(&mut out, 0x0606_4b50);
    out.extend_from_slice(&44u64.to_le_bytes());
    u16le(&mut out, 45);
    u16le(&mut out, 45);
    u32le(&mut out, 0);
    u32le(&mut out, 0);
    out.extend_from_slice(&entries.to_le_bytes());
    out.extend_from_slice(&entries.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    u32le(&mut out, 0x0706_4b50);
    u32le(&mut out, 0);
    out.extend_from_slice(&record_offset.to_le_bytes());
    u32le(&mut out, 1);
    u32le(&mut out, 0x0605_4b50);
    u16le(&mut out, 0);
    u16le(&mut out, 0);
    u16le(&mut out, u16::MAX);
    u16le(&mut out, u16::MAX);
    u32le(&mut out, u32::MAX);
    u32le(&mut out, u32::MAX);
    u16le(&mut out, 0);
    out
}

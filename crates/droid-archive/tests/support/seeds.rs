// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Starting corpus for the fuzzing targets, built with the same builders as
//! the integration tests: one valid archive and one archive per family of
//! hostile constructs. Nothing here is stored in the repository; the nightly
//! fuzzing workflow writes these archives to disk before each run.

use super::{
    EntrySpec, FLAG_ENCRYPTED, ZipBuilder, bare_central_record, into_zip64, sample, signing_block,
};

/// Every seed is at most this long, so that libFuzzer never truncates one
/// (the workflow runs with `-max_len=70000`).
pub const MAX_SEED_LEN: usize = 70_000;

/// Returns the seeds as (file name, content) pairs. File names are unique.
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    let mut seeds = Vec::new();

    let mut signed = sample();
    signed.before_central_directory = signing_block();
    seeds.push(("valid-signed.zip", signed.build()));

    seeds.push(("zip64.zip", into_zip64(&sample().build())));

    let mut prefixed = sample();
    prefixed.prefix = b"#!/bin/sh\nexit 0\n".to_vec();
    seeds.push(("prefix-adjusted.zip", prefixed.build()));

    let mut shifted = sample();
    shifted.prefix = vec![0xAA; 100];
    shifted.offsets_include_prefix = false;
    seeds.push(("prefix-shifted.zip", shifted.build()));

    let mut decoy = sample();
    decoy.prefix = ZipBuilder::new()
        .entry(EntrySpec::stored("AndroidManifest.xml", b"decoy"))
        .build();
    seeds.push(("prefix-decoy-archive.zip", decoy.build()));

    let mut trailer = sample();
    trailer.trailer = b"appended".to_vec();
    trailer.comment = b"built by hand".to_vec();
    seeds.push(("comment-and-trailer.zip", trailer.build()));

    let mut fake_end = sample();
    fake_end.comment = ZipBuilder::new().build();
    seeds.push(("comment-fake-eocd.zip", fake_end.build()));

    let mut max_comment = sample();
    max_comment.comment = vec![b'c'; 0xFFFF];
    seeds.push(("comment-max-length.zip", max_comment.build()));

    let mut multi_disk = sample();
    multi_disk.eocd.disk = Some(1);
    multi_disk.eocd.entries_on_disk = Some(2);
    seeds.push(("multi-disk.zip", multi_disk.build()));

    let mut hidden = sample();
    hidden.central_directory_tail = bare_central_record(b"hidden.dex");
    hidden.after_central_directory = vec![0; 5];
    seeds.push(("central-directory-hidden-record.zip", hidden.build()));

    let unreferenced = ZipBuilder::new()
        .entry(EntrySpec::stored("classes2.dex", b"hidden"))
        .build();
    let mut gap = sample();
    gap.before_central_directory = unreferenced
        .get(..unreferenced.len().checked_sub(22).unwrap())
        .unwrap()
        .to_vec();
    seeds.push(("unreferenced-local-header.zip", gap.build()));

    let mut bad_block = signing_block();
    bad_block[0] ^= 0x01;
    let mut malformed = sample();
    malformed.before_central_directory = bad_block;
    seeds.push(("signing-block-malformed.zip", malformed.build()));

    seeds.push((
        "duplicate-names.zip",
        sample()
            .entry(EntrySpec::stored("AndroidManifest.xml", b"<evil/>"))
            .entry(EntrySpec::stored("ANDROIDMANIFEST.XML", b"<case/>"))
            .build(),
    ));

    let mut method = EntrySpec::stored("AndroidManifest.xml", b"<manifest/>");
    method.local.method = Some(8);
    let mut name = EntrySpec::stored("res/a.xml", b"<a/>");
    name.local.name = Some(b"res/b.xml".to_vec());
    let mut sizes = EntrySpec::deflated("classes.dex", &[7u8; 300]);
    sizes.local.uncompressed_size = Some(10);
    sizes.local.crc32 = Some(1);
    let mut flags = EntrySpec::stored("assets/a", b"a");
    flags.local.flags = Some(0x0800);
    let mut missing = EntrySpec::stored("assets/b", b"b");
    missing.local_header_offset = Some(3);
    seeds.push((
        "local-header-mismatches.zip",
        ZipBuilder::new()
            .entry(method)
            .entry(name)
            .entry(sizes)
            .entry(flags)
            .entry(missing)
            .build(),
    ));

    let mut encrypted = EntrySpec::deflated("classes.dex", b"not encrypted at all");
    encrypted.flags |= FLAG_ENCRYPTED;
    let mut unknown = EntrySpec::stored("lib/arm64-v8a/libfoo.so", b"\x7fELF");
    unknown.method = 0x1337;
    unknown.local.method = Some(0x1337);
    let mut inconsistent = EntrySpec::stored("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n");
    inconsistent.compressed_size = 4;
    seeds.push((
        "methods-and-flags.zip",
        ZipBuilder::new()
            .entry(encrypted)
            .entry(unknown)
            .entry(inconsistent)
            .build(),
    ));

    let mut bad_descriptor = EntrySpec::deflated("classes.dex", b"aaaa").with_data_descriptor(true);
    let last = bad_descriptor.data_descriptor.len().checked_sub(1).unwrap();
    bad_descriptor.data_descriptor[last] = 0x7F;
    let mut understated = EntrySpec::deflated("res/raw/u.bin", &[1u8; 500]);
    understated.uncompressed_size = 100;
    let mut corrupt = EntrySpec::deflated("res/raw/c.bin", b"corrupt me please");
    corrupt.payload[0] ^= 0xFF;
    let mut trailing = EntrySpec::deflated("res/raw/t.bin", b"trailing");
    trailing.payload.extend_from_slice(b"extra");
    trailing.compressed_size = trailing.compressed_size.checked_add(5).unwrap();
    let mut wrong_crc = EntrySpec::stored("res/raw/crc.bin", b"crc");
    wrong_crc.crc32 ^= 1;
    wrong_crc.local.crc32 = Some(wrong_crc.crc32);
    seeds.push((
        "content-errors.zip",
        ZipBuilder::new()
            .entry(bad_descriptor)
            .entry(understated)
            .entry(corrupt)
            .entry(trailing)
            .entry(wrong_crc)
            .build(),
    ));

    seeds.push((
        "decompression-bomb.zip",
        ZipBuilder::new()
            .entry(EntrySpec::deflated("assets/zeros", &vec![0u8; 2 << 20]))
            .build(),
    ));

    let mut symlink = EntrySpec::stored("lib/arm64-v8a/libbar.so", b"/data/data/x");
    symlink.external_attributes = 0o120_777 << 16;
    let mut builder = ZipBuilder::new();
    for name in [
        "../../data/system/evil",
        "/system/bin/sh",
        "C:\\Windows\\evil.dll",
        "assets\\..\\..\\evil",
        "",
    ] {
        builder = builder.entry(EntrySpec::stored(name, b"x"));
    }
    builder = builder
        .entry(symlink)
        .entry(EntrySpec::stored("x", b"1").with_name_bytes(b"a\0b"))
        .entry(EntrySpec::stored("x", b"2").with_name_bytes(&[b'a', 0xC0, 0xAF]))
        .entry(EntrySpec::stored(
            &format!("assets/{}.bin", "b".repeat(300)),
            b"x",
        ));
    seeds.push(("hostile-names.zip", builder.build()));

    let inner = EntrySpec::stored("inner", b"shared");
    let inner_archive = ZipBuilder::new().entry(inner.clone()).build();
    let outer = EntrySpec::stored("o", inner_archive.get(..30 + 5 + 6).unwrap());
    let mut shadow = inner;
    shadow.central_only = true;
    shadow.local_header_offset = Some(30 + 1);
    seeds.push((
        "overlapping-entries.zip",
        ZipBuilder::new().entry(outer).entry(shadow).build(),
    ));

    let mut components = ZipBuilder::new()
        .entry(EntrySpec::stored("AndroidManifest.xml", b"<manifest/>"))
        .entry(EntrySpec::deflated("classes.dex", b"dex\n035\0"))
        .entry(EntrySpec::deflated("classes2.dex", b"dex\n035\0"))
        .entry(EntrySpec::deflated("classes4.dex", b"dex\n035\0"))
        .entry(EntrySpec::deflated("classes02.dex", b"dex\n035\0"))
        .entry(EntrySpec::deflated("lib/x86_64/libfoo.so", b"\x7fELF"))
        .entry(EntrySpec::deflated("lib/x86_64/sub/libbar.so", b"\x7fELF"))
        .entry(EntrySpec::deflated(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\n",
        ))
        .entry(EntrySpec::deflated("META-INF/CERT.RSA", b"0\x82"));
    components.before_central_directory = signing_block();
    seeds.push(("components.zip", components.build()));

    seeds.push(("empty.zip", ZipBuilder::new().build()));

    seeds
}

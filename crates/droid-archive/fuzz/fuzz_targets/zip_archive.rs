// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Parses arbitrary bytes as a ZIP archive, reads every entry, and checks the
//! invariants the reader promises.

#![no_main]

use std::collections::HashMap;

use droid_archive::Limits;
use droid_archive::zip::{AnomalyKind, Component, Impact, ZipArchive};
use libfuzzer_sys::fuzz_target;

const LIMITS: Limits = Limits {
    max_entries: 4096,
    max_central_directory_size: 1 << 20,
    max_entry_size: 1 << 20,
    max_total_size: 4 << 20,
    max_compression_ratio: 100,
    compression_ratio_min_size: 4096,
};

fuzz_target!(|data: &[u8]| {
    let Ok(archive) = ZipArchive::parse(data, LIMITS) else {
        return;
    };
    let len = data.len() as u64;
    let entries = archive.entries();
    assert!(entries.len() as u64 <= LIMITS.max_entries);
    assert!(archive.layout().central_directory_size <= LIMITS.max_central_directory_size);
    let mut dex_gap = None;
    let mut duplicates: Vec<Option<usize>> = vec![None; entries.len()];
    let mut dex_prefixes = 0usize;
    for anomaly in archive.anomalies() {
        let expected_vulnerabilities: &[&str] = match anomaly.kind {
            AnomalyKind::DuplicateName { .. } => &["CVE-2013-4787"],
            AnomalyKind::DexPrefix => &["CVE-2017-13156", "CVE-2024-40673"],
            AnomalyKind::DexPrefixRelocated => &["CVE-2024-40673"],
            AnomalyKind::NameLengthOverflow { .. } => &["CVE-2026-58995"],
            _ => &[],
        };
        assert_eq!(anomaly.known_vulnerabilities(), expected_vulnerabilities);
        if let AnomalyKind::DuplicateName { first } = anomaly.kind {
            let index = anomaly.entry.expect("duplicate names name an entry");
            assert!(first < index);
            assert_eq!(entries[first].name, entries[index].name);
            assert_eq!(anomaly.impact(), Impact::ArchiveRejected);
            assert!(duplicates[index].replace(first).is_none());
        }
        if matches!(
            anomaly.kind,
            AnomalyKind::DexPrefix | AnomalyKind::DexPrefixRelocated
        ) {
            assert!(data.starts_with(b"dex\n"));
            assert_eq!(anomaly.entry, None);
            assert_eq!(anomaly.component, None);
            assert_eq!(anomaly.impact(), Impact::ArchiveRejected);
            let layout = archive.layout();
            let classic = layout.offset_shift == 0 && layout.zip64_eocd_offset.is_none();
            assert_eq!(classic, anomaly.kind == AnomalyKind::DexPrefix);
            assert!(
                archive
                    .anomalies()
                    .iter()
                    .any(|other| matches!(other.kind, AnomalyKind::PrefixData { .. }))
            );
            dex_prefixes += 1;
        }
        assert!(anomaly.entry.is_none_or(|index| index < entries.len()));
        if let AnomalyKind::DexUnreachable { missing } = anomaly.kind {
            let index = anomaly
                .entry
                .expect("unreachable DEX anomalies name an entry");
            assert_eq!(entries[index].component, Component::Dex);
            assert!(dex_gap.is_none_or(|gap| gap == missing));
            dex_gap = Some(missing);
        }
        if let AnomalyKind::NameLengthOverflow {
            lib_prefix,
            bc_suffix,
        } = anomaly.kind
        {
            let index = anomaly.entry.expect("name length overflows name an entry");
            let name = &entries[index].name;
            assert_eq!(name.len(), usize::from(u16::MAX));
            assert_eq!(lib_prefix, name.starts_with(b"lib/"));
            assert_eq!(bc_suffix, name.ends_with(b".bc"));
            assert!(lib_prefix || bc_suffix);
            assert_eq!(anomaly.component, Some(Component::NativeLibraries));
            assert_eq!(anomaly.impact(), Impact::Suspicious);
            assert_eq!(anomaly.known_vulnerabilities(), ["CVE-2026-58995"]);
            assert!(archive.entry_anomalies(index).all(|other| !matches!(
                other.kind,
                AnomalyKind::InvalidName
                    | AnomalyKind::LocalHeaderMissing
                    | AnomalyKind::LocalNameMismatch
            )));
        }
        if let Some(index) = anomaly.entry {
            let component = anomaly.component.expect("entry anomalies name a component");
            assert!(
                component == entries[index].component
                    || component == Component::JarSignature
                    || matches!(anomaly.kind, AnomalyKind::NameLengthOverflow { .. })
            );
        }
        for id in anomaly.known_vulnerabilities() {
            assert!(id.starts_with("CVE-"));
        }
        assert!(!anomaly.code().is_empty());
        let _ = anomaly.to_string();
    }
    let mut first_of: HashMap<&[u8], usize> = HashMap::new();
    for entry in entries {
        let first = *first_of.entry(entry.name.as_slice()).or_insert(entry.index);
        let expected = (first != entry.index).then_some(first);
        assert_eq!(duplicates[entry.index], expected);
    }
    let expected_prefixes = archive.layout().declared_entries > 0 && data.starts_with(b"dex\n");
    assert_eq!(dex_prefixes, usize::from(expected_prefixes));
    if let Some(missing) = dex_gap {
        let name = match missing {
            1 => "classes.dex".to_string(),
            n => format!("classes{n}.dex"),
        };
        assert!(archive.find(name.as_bytes()).is_none());
    }
    let layout = archive.layout();
    assert!(layout.central_directory_offset <= len);
    assert!(layout.comment.start <= layout.comment.end && layout.comment.end <= len);
    let _ = archive.comment();
    let _ = archive.android_accepts();

    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.index, index);
        assert!(entry.name.len() <= usize::from(u16::MAX));
        assert!(entry.data_offset.is_none_or(|offset| offset <= len));
        let _ = entry.name_lossy();
        let before = archive.total_read();
        if let Ok(content) = archive.read(index) {
            let produced = content.data.len() as u64;
            assert_eq!(produced, entry.uncompressed_size);
            assert!(produced <= LIMITS.max_entry_size);
            assert_eq!(archive.total_read(), before + produced);
            for anomaly in &content.anomalies {
                assert_eq!(anomaly.entry, Some(index));
                assert_eq!(anomaly.component, Some(entry.component));
            }
        }
        assert!(archive.total_read() <= LIMITS.max_total_size);
    }
});

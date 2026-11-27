// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Parses arbitrary bytes as a ZIP archive, reads every entry, and checks the
//! invariants the reader promises.

#![no_main]

use droid_archive::Limits;
use droid_archive::zip::{AnomalyKind, Component, ZipArchive};
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
    for anomaly in archive.anomalies() {
        assert!(anomaly.entry.is_none_or(|index| index < entries.len()));
        if let AnomalyKind::DexUnreachable { missing } = anomaly.kind {
            let index = anomaly
                .entry
                .expect("unreachable DEX anomalies name an entry");
            assert_eq!(entries[index].component, Component::Dex);
            assert!(dex_gap.is_none_or(|gap| gap == missing));
            dex_gap = Some(missing);
        }
        if let Some(index) = anomaly.entry {
            let component = anomaly.component.expect("entry anomalies name a component");
            assert!(component == entries[index].component || component == Component::JarSignature);
        }
        assert!(!anomaly.code().is_empty());
        let _ = anomaly.to_string();
    }
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

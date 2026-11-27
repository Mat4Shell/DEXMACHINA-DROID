// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Checks the starting corpus of the fuzzing targets, and writes it to disk
//! for the nightly fuzzing workflow.

#![cfg(test)]

mod support;

use std::collections::HashSet;
use std::path::PathBuf;

use droid_archive::Limits;
use droid_archive::zip::ZipArchive;
use support::seeds::{self, MAX_SEED_LEN};

/// Directory the ignored test writes the seeds to.
const SEEDS_DIR_VAR: &str = "DROID_FUZZ_SEEDS_DIR";

#[test]
fn seeds_are_distinct_and_exercise_the_reader() {
    let seeds = seeds::all();
    let mut names = HashSet::new();
    let mut contents = HashSet::new();
    let mut opened = 0;
    for (name, data) in &seeds {
        assert!(names.insert(*name), "duplicate seed name {name}");
        assert!(contents.insert(data.clone()), "duplicate seed {name}");
        assert!(data.len() <= MAX_SEED_LEN, "{name} is {} bytes", data.len());
        if let Ok(archive) = ZipArchive::parse(data, Limits::default()) {
            opened += 1;
            for index in 0..archive.entries().len() {
                let _ = archive.read(index);
            }
        }
    }
    assert_eq!(opened, seeds.len(), "every seed should open");
}

#[test]
#[ignore = "writes files; run by the fuzzing workflow with DROID_FUZZ_SEEDS_DIR set"]
fn write_fuzz_seeds() {
    let dir = PathBuf::from(
        std::env::var_os(SEEDS_DIR_VAR).expect("DROID_FUZZ_SEEDS_DIR names the output directory"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    for (name, data) in seeds::all() {
        std::fs::write(dir.join(name), data).unwrap();
    }
}

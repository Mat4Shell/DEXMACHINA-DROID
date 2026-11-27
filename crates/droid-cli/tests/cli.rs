// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

use std::error::Error;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

fn droid(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_droid"))
        .args(args)
        .output()
}

#[test]
fn version_prints_name_and_version() -> TestResult {
    let output = droid(&["--version"])?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(
        stdout.trim(),
        format!("droid {}", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn help_prints_usage_and_legal_notice() -> TestResult {
    let output = droid(&["--help"])?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Usage: droid"));
    assert!(stdout.contains("DEX MACHINA, by Mat4Shell"));
    assert!(stdout.contains("https://github.com/Mat4Shell/dexmachina-droid"));
    Ok(())
}

#[test]
fn unknown_argument_is_rejected() -> TestResult {
    let output = droid(&["--no-such-flag"])?;
    assert!(!output.status.success());
    Ok(())
}

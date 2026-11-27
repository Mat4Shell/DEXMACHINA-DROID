// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! The `droid` command-line tool.

#![forbid(unsafe_code)]

use clap::Parser;

const LEGAL_NOTICE: &str = "\
DEX MACHINA, by Mat4Shell (https://mat4shell.com)
Source: https://github.com/Mat4Shell/dexmachina-droid
License: AGPL-3.0-or-later, with a commercial license available.";

/// Android application security analyzer.
#[derive(Debug, Parser)]
#[command(name = "droid", version, after_help = LEGAL_NOTICE)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}

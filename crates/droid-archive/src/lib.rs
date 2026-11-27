// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Defensive reader for APK, XAPK, APKS and AAB archives.
//!
//! The [`zip`] module reads the ZIP container the way Android does, and
//! reports every construction that Android rejects or reads differently from
//! a general-purpose ZIP reader. All reads happen in memory, under the
//! [`Limits`] given by the caller; nothing is ever written to disk.

#![forbid(unsafe_code)]

mod limits;
pub mod zip;

pub use limits::Limits;

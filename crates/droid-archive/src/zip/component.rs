// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! The Android components that read an APK.
//!
//! All of them locate entries through the same ZIP library, but they read
//! entry content in different ways, so the same anomaly can mean different
//! things depending on the entry and on who reads it.

/// An Android component that reads the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Component {
    /// The resource loader (`libandroidfw`), which reads the manifest,
    /// `resources.arsc`, resources and assets. It inflates method 8 and reads
    /// any other method as stored, without checking data descriptors.
    Resources,
    /// ART, which loads `classes.dex`, `classes2.dex` and so on. It maps
    /// aligned stored entries directly and extracts the others through the ZIP
    /// library, which only knows the stored and deflate methods.
    Dex,
    /// The installer and the dynamic linker, for `lib/<abi>/<name>` entries.
    /// Libraries are extracted through the ZIP library, or loaded in place
    /// when stored and page-aligned.
    NativeLibraries,
    /// The JAR signature verifier (APK Signature Scheme v1), which reads the
    /// signature files and digests every entry. It reads stored entries as is
    /// and inflates every other method.
    JarSignature,
    /// The APK Signature Scheme v2 and v3 verifiers, which locate the end of
    /// central directory with their own code and reject ZIP64 archives.
    SigningBlock,
}

impl Component {
    /// Stable identifier of the component.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Resources => "resources",
            Self::Dex => "dex",
            Self::NativeLibraries => "native_libraries",
            Self::JarSignature => "jar_signature",
            Self::SigningBlock => "signing_block",
        }
    }

    /// The component that Android uses to read an entry with this name.
    pub fn for_entry(name: &[u8]) -> Self {
        if is_dex_name(name) {
            Self::Dex
        } else if is_native_library_name(name) {
            Self::NativeLibraries
        } else if is_jar_signature_name(name) {
            Self::JarSignature
        } else {
            Self::Resources
        }
    }
}

/// ART loads `classes.dex`, then `classes2.dex`, `classes3.dex` and so on.
fn is_dex_name(name: &[u8]) -> bool {
    let Some(number) = name
        .strip_prefix(b"classes")
        .and_then(|rest| rest.strip_suffix(b".dex"))
    else {
        return false;
    };
    match number {
        [] => true,
        [b'0', ..] => false,
        digits => digits.iter().all(u8::is_ascii_digit) && digits != b"1",
    }
}

/// Position of a DEX entry in ART's loading order: 1 for `classes.dex`, `N`
/// for `classesN.dex`. `None` when the name is not one that ART loads, or
/// when its number does not fit in a `u64`.
pub(crate) fn dex_number(name: &[u8]) -> Option<u64> {
    if !is_dex_name(name) {
        return None;
    }
    let digits = name.strip_prefix(b"classes")?.strip_suffix(b".dex")?;
    if digits.is_empty() {
        return Some(1);
    }
    digits.iter().try_fold(0u64, |number, &digit| {
        number
            .checked_mul(10)?
            .checked_add(u64::from(digit.checked_sub(b'0')?))
    })
}

/// The name of the DEX entry at this position in ART's loading order.
pub(crate) fn dex_name(number: u64) -> String {
    if number == 1 {
        "classes.dex".to_string()
    } else {
        format!("classes{number}.dex")
    }
}

/// The installer only considers `lib/<abi>/<file>`, with no subdirectory.
fn is_native_library_name(name: &[u8]) -> bool {
    let Some(rest) = name.strip_prefix(b"lib/") else {
        return false;
    };
    let mut parts = rest.split(|&b| b == b'/');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(abi), Some(file), None) if !abi.is_empty() && !file.is_empty()
    )
}

/// The manifest and signature files that the JAR verifier reads.
fn is_jar_signature_name(name: &[u8]) -> bool {
    let Some(file) = name.strip_prefix(b"META-INF/") else {
        return false;
    };
    if file.contains(&b'/') {
        return false;
    }
    let upper = file.to_ascii_uppercase();
    upper == b"MANIFEST.MF"
        || [b".SF".as_slice(), b".RSA", b".DSA", b".EC"]
            .iter()
            .any(|suffix| upper.len() > suffix.len() && upper.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::{Component, dex_name, dex_number};

    #[test]
    fn classifies_entries() {
        let cases: [(&[u8], Component); 14] = [
            (b"classes.dex", Component::Dex),
            (b"classes2.dex", Component::Dex),
            (b"classes10.dex", Component::Dex),
            (b"classes1.dex", Component::Resources),
            (b"classes02.dex", Component::Resources),
            (b"assets/classes.dex", Component::Resources),
            (b"lib/arm64-v8a/libfoo.so", Component::NativeLibraries),
            (b"lib/x86/sub/libfoo.so", Component::Resources),
            (b"lib/libfoo.so", Component::Resources),
            (b"META-INF/MANIFEST.MF", Component::JarSignature),
            (b"META-INF/CERT.RSA", Component::JarSignature),
            (b"META-INF/cert.sf", Component::JarSignature),
            (b"META-INF/services/x", Component::Resources),
            (b"AndroidManifest.xml", Component::Resources),
        ];
        for (name, component) in cases {
            assert_eq!(
                Component::for_entry(name),
                component,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn numbers_dex_entries_in_loading_order() {
        let cases: [(&[u8], Option<u64>); 8] = [
            (b"classes.dex", Some(1)),
            (b"classes2.dex", Some(2)),
            (b"classes10.dex", Some(10)),
            (b"classes18446744073709551615.dex", Some(u64::MAX)),
            (b"classes18446744073709551616.dex", None),
            (b"classes1.dex", None),
            (b"classes02.dex", None),
            (b"assets/classes2.dex", None),
        ];
        for (name, number) in cases {
            assert_eq!(
                dex_number(name),
                number,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        assert_eq!(dex_name(1), "classes.dex");
        assert_eq!(dex_name(3), "classes3.dex");
    }
}

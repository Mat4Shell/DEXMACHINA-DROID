// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Mathias EMON (Mat4Shell)

//! Checks on entry names.

/// Android's entry name check (`IsValidEntryName` in libziparchive): no NUL
/// byte, and a permissive UTF-8 check that only verifies the structure of
/// continuation bytes. It accepts overlong forms, surrogates and five-byte
/// sequences.
pub(crate) fn is_valid_for_android(name: &[u8]) -> bool {
    let mut bytes = name.iter();
    while let Some(&byte) = bytes.next() {
        if byte == 0 {
            return false;
        }
        if byte & 0x80 == 0 {
            continue;
        }
        if byte & 0xC0 == 0x80 || byte & 0xFE == 0xFE {
            return false;
        }
        // Each leading one bit after the first announces a continuation byte.
        let mut lead = (byte & 0x7F) << 1;
        while lead & 0x80 != 0 {
            match bytes.next() {
                Some(&next) if next & 0xC0 == 0x80 => {}
                _ => return false,
            }
            lead = (lead & 0x7F) << 1;
        }
    }
    true
}

/// Whether a path component of the name is `..`, with `/` or `\` as
/// separators.
pub(crate) fn has_parent_component(name: &[u8]) -> bool {
    name.split(|&b| b == b'/' || b == b'\\')
        .any(|component| component == b"..")
}

/// Length of the longest path component, with `/` or `\` as separators.
pub(crate) fn longest_component(name: &[u8]) -> usize {
    name.split(|&b| b == b'/' || b == b'\\')
        .map(<[u8]>::len)
        .max()
        .unwrap_or_default()
}

/// Whether the name is absolute on Unix or on Windows.
pub(crate) fn is_absolute(name: &[u8]) -> bool {
    match name {
        [b'/' | b'\\', ..] => true,
        [drive, b':', ..] => drive.is_ascii_alphabetic(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_check_is_permissive() {
        assert!(is_valid_for_android(b"res/layout/main.xml"));
        assert!(is_valid_for_android("caf\u{e9}".as_bytes()));
        // Overlong encoding of '/', rejected by strict UTF-8.
        assert!(is_valid_for_android(&[0xC0, 0xAF]));
        // Encoded surrogate.
        assert!(is_valid_for_android(&[0xED, 0xA0, 0x80]));
        // Five-byte sequence.
        assert!(is_valid_for_android(&[0xF8, 0x88, 0x80, 0x80, 0x80]));
        assert!(!is_valid_for_android(b"a\0b"));
        assert!(!is_valid_for_android(&[0x80]));
        assert!(!is_valid_for_android(&[0xC3]));
        assert!(!is_valid_for_android(&[0xC3, 0x41]));
        assert!(!is_valid_for_android(&[0xFE]));
        assert!(!is_valid_for_android(&[0xFF]));
    }

    #[test]
    fn detects_hostile_paths() {
        assert!(has_parent_component(b"../evil"));
        assert!(has_parent_component(b"a/../../b"));
        assert!(has_parent_component(b"a\\..\\b"));
        assert!(has_parent_component(b".."));
        assert!(!has_parent_component(b"a/..b/c"));
        assert!(!has_parent_component(b"lib/x86/lib...so"));
        assert!(is_absolute(b"/etc/passwd"));
        assert!(is_absolute(b"\\windows"));
        assert!(is_absolute(b"C:\\x"));
        assert!(is_absolute(b"c:x"));
        assert!(!is_absolute(b"assets/a:b"));
        assert!(!is_absolute(b""));
    }

    #[test]
    fn measures_components() {
        assert_eq!(longest_component(b""), 0);
        assert_eq!(longest_component(b"res/layout/main.xml"), 8);
        assert_eq!(longest_component(b"a\\bbbb/cc"), 4);
    }
}

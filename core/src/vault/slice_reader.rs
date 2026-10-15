//! Allocation-safe reads from already buffered vault payloads.

use std::io::{self, Cursor};

use crate::error::DiaryError;

/// Copy a field only after proving that its complete range is present.
/// Callers retain their format-specific field-size limits. Generic streaming
/// readers cannot make this remaining-length check and are intentionally separate.
pub(super) fn read_vec(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, DiaryError> {
    // Match the previous helper's zero-length behavior, even past EOF.
    if len == 0 {
        return Ok(Vec::new());
    }
    let range = usize::try_from(cursor.position())
        .ok()
        .and_then(|start| start.checked_add(len).map(|end| start..end));
    let Some(bytes) = range.and_then(|range| cursor.get_ref().get(range)) else {
        // Cursor::read_exact moves to the slice end on a short read.
        // Preserve that behavior without allocating a destination buffer.
        cursor.set_position(cursor.get_ref().len() as u64);
        return Err(
            io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer").into(),
        );
    };
    // No attacker-sized allocation occurs until the bounds check above succeeds.
    let out = bytes.to_vec();
    cursor.set_position(cursor.position() + len as u64);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn reads_exact_ranges_and_advances_by_field_length() {
        let mut cursor = Cursor::new(&b"abcdef"[..]);
        cursor.set_position(1);
        assert_eq!(read_vec(&mut cursor, 2).unwrap(), b"bc");
        assert_eq!(cursor.position(), 3);
        assert!(read_vec(&mut cursor, 0).unwrap().is_empty());
        assert_eq!(cursor.position(), 3);
        assert_eq!(read_vec(&mut cursor, 3).unwrap(), b"def");
        assert_eq!(cursor.position(), 6);
    }

    #[test]
    fn truncated_ranges_match_read_exact_progress_and_diagnostics() {
        for position in [0, 1, 3, 4, u64::MAX] {
            let mut cursor = Cursor::new(&b"abc"[..]);
            cursor.set_position(position);
            let mut reference = cursor.clone();
            let expected = reference.read_exact(&mut [0; 4]).unwrap_err();
            let DiaryError::Io(actual) = read_vec(&mut cursor, 4).unwrap_err() else {
                panic!("expected I/O error");
            };
            assert_eq!(actual.kind(), expected.kind());
            assert_eq!(actual.to_string(), expected.to_string());
            assert_eq!(cursor.position(), reference.position());
        }
    }

    #[test]
    fn overclaimed_and_overflowing_lengths_fail_before_copying() {
        let mut cursor = Cursor::new(&b"abc"[..]);
        cursor.set_position(1);
        for len in [16 * 1024 * 1024, usize::MAX] {
            assert!(matches!(read_vec(&mut cursor, len), Err(DiaryError::Io(e))
                if e.kind() == io::ErrorKind::UnexpectedEof));
            assert_eq!(cursor.position(), 3);
        }
        cursor.set_position(u64::MAX);
        assert!(read_vec(&mut cursor, 0).unwrap().is_empty());
        assert_eq!(cursor.position(), u64::MAX);
    }
}

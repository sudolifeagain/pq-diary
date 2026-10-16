# Search plaintext ownership

Search decrypts and scans one record at a time, but keeps matching titles and
context text in the returned results. Context can include an entire body.
Result memory therefore grows with the accumulated output, not just one entry.

`SearchMatch` and `ContextBlock` implement `Zeroize` and `ZeroizeOnDrop`.
Their owned title and context strings are wiped when the owners are dropped,
including partial results discarded by an error. Matching-tag selection borrows
from the decrypted entry instead of keeping an unprotected cloned tag list.
`Debug` for both owners is redacted; explicit field access and the CLI's intended
search display remain unchanged. UUIDs, timestamps, line positions and field
labels are not treated as secret body text.

## Source compatibility

Public field names and types remain unchanged, including `String` titles and
`Vec<(usize, String, bool)>` context lines. Existing struct literals and borrowing
consumers (including the CLI) still work. Adding `Drop` does prevent moving fields
out of an owned `SearchMatch` or `ContextBlock` by destructuring. Prefer borrowing:

```rust
# use pq_diary_core::search::SearchMatch;
fn display_title(found: &SearchMatch) {
    println!("{}", found.title);
}
```

A consumer that genuinely needs independent ownership may clone or use
`std::mem::take`, but must immediately protect the returned secret-bearing value,
for example `Zeroizing::new(std::mem::take(&mut found.title))`. Likewise, strings
explicitly cloned, removed or replaced through public fields are the caller's
responsibility. These public fields do not enforce secrecy after arbitrary
caller mutations. The same rule applies to manually constructing detached lines.

The importer also protects the owned intermediate link-rewritten body until tag
extraction finishes, including error exits. This does not change its public API,
frontmatter parsing, or Markdown rewriting behavior.
Import also guards metadata through rewrites and tag merging, wipes discarded
duplicate tags, and borrows tag-deduplication keys from the protected input.

These are ownership-lifetime guarantees for these explicit buffers, not a claim
that compiler, allocator, regex engine or terminal/output copies can all be
removed. CLI output is intentionally plaintext; query storage and other public
metadata owners are outside this focused change. Tests check trait contracts,
live-buffer zeroization and redacted formatting, never freed memory.

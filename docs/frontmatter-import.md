# Markdown frontmatter compatibility

Import reads `title:` and `tags:` from a leading `---` block. This is a
limited scalar/list format, not a general YAML implementation:

- Plain, unquoted titles and tag values keep their legacy interpretation.
- Double-quoted values use JSON string escapes, including backslash, quote,
  newline and Unicode escapes. This decodes the strings written by export.
- Single-quoted values use doubled apostrophes (`'it''s'`).
- Tags support inline comma-separated lists and block `- value` lists.
  Commas within quoted tags are literal; quoted empty titles/tags are retained.
- Malformed supported quoted scalars/lists fail import without echoing their
  contents. The source files and vault remain unchanged, including when an
  earlier file in the same import batch was valid.

Multiline YAML scalars, anchors, objects, comments after quoted values, and
YAML-specific double-quote escapes are not supported. Export's existing
control-character filtering and separating newline before the body are
unchanged. Import creates new entry identities/timestamps and retains its
existing Markdown body conversions; this is not a lossless vault backup format.

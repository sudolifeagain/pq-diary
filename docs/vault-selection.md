# Vault selection

Entry commands and `info` resolve `--vault` as follows:

- No flag: load `config.toml` from the app home and open
  `vaults/<app.default_vault>/vault.pqd`. The app home is
  `~/.pq-diary`, or `PQ_DIARY_HOME` when set. Missing or invalid
  configuration is an error; the current directory is never a fallback.
  `app.default_vault` must be a valid single vault name, using the same
  validation as `vault create`; absolute paths and path traversal are rejected.
  Unicode names and spaces are supported.
- An existing directory, including a directory whose name ends in `.pqd`:
  open its `vault.pqd`.
- Another path ending in `.pqd`: open exactly that file, using the
  `vault.toml` in its parent directory.
- Any other path: treat it as a directory and append `vault.pqd`.

`init` initializes the app home and its default vault. It rejects `--vault`;
use `vault create <name>` to create another named vault. The `vault`
management subcommands operate on a collection of vault directories;
their `--vault` specifies the collection base directory (default: CWD).

## Custom filenames

Entry-only operations and `info` support an explicit custom `.pqd` filename.
Operations backed by directory-only APIs require the filename `vault.pqd`:
password changes, legacy operations, attachment operations, import, export,
and Git operations. They reject custom filenames instead of silently opening
a sibling `vault.pqd`. `new --attach` rejects such a target before creating
an entry. `show` cannot display attachments from a custom-named vault and
reports an error if the selected entry has attachments.

For full functionality, keep each vault in its own directory with the
standard `vault.pqd` and `vault.toml` names. Do not rename a vault over an
existing sibling file.

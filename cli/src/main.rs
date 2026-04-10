mod commands;
mod editor;
mod password;

use clap::{Args, Parser, Subcommand};

/// Post-quantum cryptography CLI journal.
#[derive(Debug, Parser)]
#[command(
    name = "pq-diary",
    version,
    about = "Post-quantum cryptography CLI journal"
)]
pub struct Cli {
    /// Vault path or name
    #[arg(short = 'v', long, global = true)]
    pub vault: Option<String>,

    /// Master password (insecure; use interactive prompt instead)
    #[arg(long, global = true)]
    pub password: Option<String>,

    /// Enable Claude AI integration
    #[arg(long, global = true)]
    pub claude: bool,

    /// Enable debug output
    #[arg(long, global = true)]
    pub debug: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Arguments for the `stats` subcommand.
#[derive(Debug, Args)]
pub struct StatsArgs {
    /// Output statistics as JSON.
    #[arg(long)]
    pub json: bool,

    /// Show ASCII heatmap of writing activity (last 52 weeks).
    #[arg(long)]
    pub heatmap: bool,
}

/// Arguments for the `import` subcommand.
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Source directory containing .md files.
    pub dir: std::path::PathBuf,

    /// Preview import without writing to vault.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for the `search` subcommand.
#[derive(Debug, Args)]
pub struct SearchArgs {
    /// Regex pattern to search for.
    pub pattern: String,

    /// Filter by tag (prefix match).
    #[arg(long)]
    pub tag: Option<String>,

    /// Number of context lines around matches (default: 2).
    #[arg(long, default_value = "2")]
    pub context: usize,

    /// Show match count only.
    #[arg(long)]
    pub count: bool,
}

/// Top-level subcommands for pq-diary.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a new vault in the current directory
    Init,

    /// Manage vaults (create, list, policy, delete)
    Vault {
        #[command(subcommand)]
        subcommand: VaultCommands,
    },

    /// Create a new diary entry
    New {
        /// Entry title (positional, optional)
        title: Option<String>,

        /// Body text; skips editor when specified
        #[arg(short, long)]
        body: Option<String>,

        /// Tag to attach (repeatable: -t tag1 -t tag2)
        #[arg(short, long = "tag")]
        tag: Vec<String>,

        /// Template name to use as initial body content
        #[arg(long)]
        template: Option<String>,
    },

    /// List diary entries
    List {
        /// Filter entries by tag (prefix match, supports nested tags)
        #[arg(long)]
        tag: Option<String>,

        /// Filter entries by title (case-insensitive partial match)
        #[arg(short, long)]
        query: Option<String>,

        /// Maximum number of entries to display
        #[arg(short, long, default_value = "20")]
        number: usize,
    },

    /// Show a diary entry
    Show {
        /// Entry ID prefix (minimum 4 hex characters)
        id: String,
    },

    /// Edit a diary entry
    Edit {
        /// Entry ID prefix (minimum 4 hex characters)
        id: String,
        /// Change the entry title
        #[arg(long)]
        title: Option<String>,
        /// Add a tag to the entry (repeatable: --add-tag t1 --add-tag t2)
        #[arg(long)]
        add_tag: Vec<String>,
        /// Remove a tag from the entry (repeatable: --remove-tag t1 --remove-tag t2)
        #[arg(long)]
        remove_tag: Vec<String>,
    },

    /// Delete a diary entry
    Delete {
        /// Entry ID prefix (minimum 4 hex characters)
        id: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Sync diary entries with configured remotes
    Sync,

    /// Export diary entries to an external format
    Export,

    /// Change the vault master password
    ChangePassword,

    /// Show vault information
    Info {
        /// Show security details
        #[arg(long)]
        security: bool,
    },

    /// Initialize a git repository for the vault
    GitInit,

    /// Push vault to the remote git repository
    GitPush,

    /// Pull vault from the remote git repository
    GitPull,

    /// Sync vault with remote (pull then push)
    GitSync,

    /// Show git sync status
    GitStatus,

    /// Manage digital legacy configuration
    Legacy {
        #[command(subcommand)]
        subcommand: LegacyCommands,
    },

    /// Access a legacy vault as a designated trustee
    LegacyAccess,

    /// Manage the background daemon
    Daemon {
        #[command(subcommand)]
        subcommand: DaemonCommands,
    },

    /// Open or create today's diary entry
    Today,

    /// Search entries by regex pattern.
    Search(SearchArgs),

    /// Show vault statistics.
    Stats(StatsArgs),

    /// Import Markdown files from a directory.
    Import(ImportArgs),

    /// Manage entry templates
    Template {
        #[command(subcommand)]
        subcommand: TemplateCommands,
    },
}

/// Subcommands for vault management.
#[derive(Debug, Subcommand)]
pub enum VaultCommands {
    /// Create a new vault
    Create {
        /// Name of the new vault
        name: String,
        /// Access policy (none, write_only, full). Default: none
        #[arg(long)]
        policy: Option<String>,
    },

    /// List all available vaults
    List,

    /// Change access policy for a vault
    Policy {
        /// Vault name
        name: String,
        /// New policy (none, write_only, full)
        policy: String,
    },

    /// Delete a vault permanently
    Delete {
        /// Name of the vault to delete
        name: String,
        /// Securely overwrite vault.pqd before deletion
        #[arg(long)]
        zeroize: bool,
    },
}

/// Subcommands for digital legacy management.
#[derive(Debug, Subcommand)]
pub enum LegacyCommands {
    /// Initialize legacy configuration
    Init,

    /// Rotate legacy trustee keys
    Rotate,

    /// Set a legacy trustee
    Set,

    /// List legacy trustees
    List,
}

/// Subcommands for daemon management.
#[derive(Debug, Subcommand)]
pub enum DaemonCommands {
    /// Start the background daemon
    Start,

    /// Stop the background daemon
    Stop,

    /// Show daemon status
    Status,

    /// Lock the vault via the daemon
    Lock,
}

/// Subcommands for template management.
#[derive(Debug, Subcommand)]
pub enum TemplateCommands {
    /// Add a new entry template
    Add {
        /// Name of the template to add
        name: String,
    },

    /// List all templates
    List,

    /// Show a template's contents
    Show {
        /// Name of the template to show
        name: String,
    },

    /// Delete a template
    Delete {
        /// Name of the template to delete
        name: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
}

fn dispatch(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Commands::New {
            title,
            body,
            tag,
            template,
        } => commands::cmd_new(
            cli,
            title.clone(),
            body.clone(),
            tag.clone(),
            template.clone(),
        ),
        Commands::Init => not_implemented("init", "Sprint 2"),
        Commands::Vault { subcommand } => match subcommand {
            VaultCommands::Create { name, policy } => {
                commands::cmd_vault_create(cli, name, policy.as_deref())
            }
            VaultCommands::List => commands::cmd_vault_list(cli),
            VaultCommands::Policy { name, policy } => commands::cmd_vault_policy(cli, name, policy),
            VaultCommands::Delete { name, zeroize } => {
                commands::cmd_vault_delete(cli, name, *zeroize)
            }
        },
        Commands::List { tag, query, number } => {
            commands::cmd_list(cli, tag.clone(), query.clone(), *number)
        }
        Commands::Show { id } => commands::cmd_show(cli, id.clone()),
        Commands::Edit {
            id,
            title,
            add_tag,
            remove_tag,
        } => commands::cmd_edit(
            cli,
            id.clone(),
            title.clone(),
            add_tag.clone(),
            remove_tag.clone(),
        ),
        Commands::Delete { id, force } => commands::cmd_delete(cli, id.clone(), *force),
        Commands::Sync => not_implemented("sync", "Sprint 8"),
        Commands::Export => not_implemented("export", "Sprint 5"),
        Commands::ChangePassword => not_implemented("change-password", "Sprint 3"),
        Commands::Info { .. } => not_implemented("info", "Sprint 2"),
        Commands::GitInit => not_implemented("git-init", "Sprint 8"),
        Commands::GitPush => not_implemented("git-push", "Sprint 8"),
        Commands::GitPull => not_implemented("git-pull", "Sprint 8"),
        Commands::GitSync => not_implemented("git-sync", "Sprint 8"),
        Commands::GitStatus => not_implemented("git-status", "Sprint 8"),
        Commands::Legacy { subcommand } => match subcommand {
            LegacyCommands::Init => not_implemented("legacy init", "Sprint 9"),
            LegacyCommands::Rotate => not_implemented("legacy rotate", "Sprint 9"),
            LegacyCommands::Set => not_implemented("legacy set", "Sprint 9"),
            LegacyCommands::List => not_implemented("legacy list", "Sprint 9"),
        },
        Commands::LegacyAccess => not_implemented("legacy-access", "Sprint 9"),
        Commands::Daemon { subcommand } => match subcommand {
            DaemonCommands::Start => not_implemented("daemon start", "Sprint 10"),
            DaemonCommands::Stop => not_implemented("daemon stop", "Sprint 10"),
            DaemonCommands::Status => not_implemented("daemon status", "Sprint 10"),
            DaemonCommands::Lock => not_implemented("daemon lock", "Sprint 10"),
        },
        Commands::Today => commands::cmd_today(cli),
        Commands::Search(args) => commands::cmd_search(cli, args),
        Commands::Stats(args) => commands::cmd_stats(cli, args),
        Commands::Import(args) => commands::cmd_import(cli, args),
        Commands::Template { subcommand } => match subcommand {
            TemplateCommands::Add { name } => commands::cmd_template_add(cli, name.clone()),
            TemplateCommands::List => commands::cmd_template_list(cli),
            TemplateCommands::Show { name } => commands::cmd_template_show(cli, name.clone()),
            TemplateCommands::Delete { name, force } => {
                commands::cmd_template_delete(cli, name.clone(), *force)
            }
        },
    }
}

/// Print a "not yet implemented" message and exit with code 1.
///
/// Returns the never type `!` which coerces to any `Result` type, allowing
/// it to be used directly in match arms that return `anyhow::Result<()>`.
fn not_implemented(cmd_name: &str, sprint: &str) -> anyhow::Result<()> {
    eprintln!("Command '{cmd_name}' is not yet implemented. Planned for {sprint}.");
    std::process::exit(1);
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    dispatch(&cli)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_help_contains_all_subcommands() {
        let result = Cli::try_parse_from(["pq-diary", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let help_text = err.to_string();
        for cmd in &[
            "init",
            "vault",
            "new",
            "list",
            "show",
            "edit",
            "delete",
            "sync",
            "export",
            "change-password",
            "info",
            "git-init",
            "git-push",
            "git-pull",
            "git-sync",
            "git-status",
            "legacy",
            "legacy-access",
            "daemon",
            "today",
            "search",
            "stats",
            "import",
            "template",
        ] {
            assert!(
                help_text.contains(cmd),
                "help text missing subcommand: {cmd}"
            );
        }
    }

    #[test]
    fn test_vault_subcommand_help() {
        let result = Cli::try_parse_from(["pq-diary", "vault", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let help_text = err.to_string();
        for sub in &["create", "list", "policy", "delete"] {
            assert!(
                help_text.contains(sub),
                "vault help missing subcommand: {sub}"
            );
        }
    }

    #[test]
    fn test_global_options_parsed() {
        let result = Cli::try_parse_from(["pq-diary", "-v", "private", "--debug", "list"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        assert_eq!(cli.vault, Some("private".to_string()));
        assert!(cli.debug);
        assert!(!cli.claude);
        assert!(cli.password.is_none());
    }

    #[test]
    fn test_nonexistent_command_returns_error() {
        let result = Cli::try_parse_from(["pq-diary", "nonexistent"]);
        assert!(result.is_err());
        assert_ne!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::DisplayHelp
        );
    }

    // -------------------------------------------------------------------------
    // VaultCommands parsing tests (TASK-0071)
    // -------------------------------------------------------------------------

    /// TC-0071-P01: `vault create <name>` parses with no policy.
    #[test]
    fn tc_0071_p01_vault_create_name_only() {
        let result = Cli::try_parse_from(["pq-diary", "vault", "create", "myvault"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Vault {
                subcommand: VaultCommands::Create { name, policy },
            } => {
                assert_eq!(name, "myvault");
                assert_eq!(policy, None);
            }
            _ => panic!("Expected VaultCommands::Create"),
        }
    }

    /// TC-0071-P02: `vault create <name> --policy full` parses name and policy.
    #[test]
    fn tc_0071_p02_vault_create_with_policy() {
        let result =
            Cli::try_parse_from(["pq-diary", "vault", "create", "myvault", "--policy", "full"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Vault {
                subcommand: VaultCommands::Create { name, policy },
            } => {
                assert_eq!(name, "myvault");
                assert_eq!(policy, Some("full".to_string()));
            }
            _ => panic!("Expected VaultCommands::Create"),
        }
    }

    /// TC-0071-P03: `vault list` parses with no arguments.
    #[test]
    fn tc_0071_p03_vault_list() {
        let result = Cli::try_parse_from(["pq-diary", "vault", "list"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        assert!(matches!(
            cli.command,
            Commands::Vault {
                subcommand: VaultCommands::List
            }
        ));
    }

    /// TC-0071-P04: `vault policy <name> <policy>` parses name and policy string.
    #[test]
    fn tc_0071_p04_vault_policy() {
        let result = Cli::try_parse_from(["pq-diary", "vault", "policy", "myvault", "write_only"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Vault {
                subcommand: VaultCommands::Policy { name, policy },
            } => {
                assert_eq!(name, "myvault");
                assert_eq!(policy, "write_only");
            }
            _ => panic!("Expected VaultCommands::Policy"),
        }
    }

    /// TC-0071-P05: `vault delete <name>` parses with zeroize=false.
    #[test]
    fn tc_0071_p05_vault_delete_no_zeroize() {
        let result = Cli::try_parse_from(["pq-diary", "vault", "delete", "myvault"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Vault {
                subcommand: VaultCommands::Delete { name, zeroize },
            } => {
                assert_eq!(name, "myvault");
                assert!(!zeroize);
            }
            _ => panic!("Expected VaultCommands::Delete"),
        }
    }

    /// TC-0071-P06: `vault delete <name> --zeroize` parses with zeroize=true.
    #[test]
    fn tc_0071_p06_vault_delete_with_zeroize() {
        let result = Cli::try_parse_from(["pq-diary", "vault", "delete", "myvault", "--zeroize"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Vault {
                subcommand: VaultCommands::Delete { name, zeroize },
            } => {
                assert_eq!(name, "myvault");
                assert!(zeroize);
            }
            _ => panic!("Expected VaultCommands::Delete"),
        }
    }

    // -------------------------------------------------------------------------
    // Commands::New parsing tests (TASK-0037)
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Commands::Edit parsing tests (TASK-0039)
    // -------------------------------------------------------------------------

    /// TC-0039-P01: `edit <id>` with no flags parses with empty optional fields.
    #[test]
    fn tc_0039_p01_edit_id_only() {
        let result = Cli::try_parse_from(["pq-diary", "edit", "abcd1234"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Edit {
                id,
                title,
                add_tag,
                remove_tag,
            } => {
                assert_eq!(id, "abcd1234");
                assert_eq!(title, None);
                assert!(add_tag.is_empty());
                assert!(remove_tag.is_empty());
            }
            _ => panic!("Expected Commands::Edit"),
        }
    }

    /// TC-0039-P02: `edit <id> --title "new title"` parses the title flag.
    #[test]
    fn tc_0039_p02_edit_with_title_flag() {
        let result = Cli::try_parse_from(["pq-diary", "edit", "abcd", "--title", "New Title"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Edit { title, .. } => {
                assert_eq!(title, Some("New Title".to_string()));
            }
            _ => panic!("Expected Commands::Edit"),
        }
    }

    /// TC-0039-P03: `edit <id> --add-tag t1 --add-tag t2` accumulates multiple add-tag values.
    #[test]
    fn tc_0039_p03_edit_multiple_add_tag() {
        let result = Cli::try_parse_from([
            "pq-diary",
            "edit",
            "abcd",
            "--add-tag",
            "t1",
            "--add-tag",
            "t2",
        ]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Edit { add_tag, .. } => {
                assert_eq!(add_tag, vec!["t1".to_string(), "t2".to_string()]);
            }
            _ => panic!("Expected Commands::Edit"),
        }
    }

    /// TC-0039-P04: `edit <id> --remove-tag old` parses the remove-tag flag.
    #[test]
    fn tc_0039_p04_edit_remove_tag() {
        let result = Cli::try_parse_from(["pq-diary", "edit", "abcd", "--remove-tag", "old"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Edit { remove_tag, .. } => {
                assert_eq!(remove_tag, vec!["old".to_string()]);
            }
            _ => panic!("Expected Commands::Edit"),
        }
    }

    /// TC-0039-P05: Combined --title, --add-tag, and --remove-tag parse correctly.
    #[test]
    fn tc_0039_p05_edit_combined_flags() {
        let result = Cli::try_parse_from([
            "pq-diary",
            "edit",
            "abcd1234",
            "--title",
            "Updated",
            "--add-tag",
            "new",
            "--remove-tag",
            "old",
        ]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Edit {
                id,
                title,
                add_tag,
                remove_tag,
            } => {
                assert_eq!(id, "abcd1234");
                assert_eq!(title, Some("Updated".to_string()));
                assert_eq!(add_tag, vec!["new".to_string()]);
                assert_eq!(remove_tag, vec!["old".to_string()]);
            }
            _ => panic!("Expected Commands::Edit"),
        }
    }

    /// TC-0037-P01: `new` with no arguments parses with all defaults.
    #[test]
    fn tc_0037_p01_new_no_args_defaults() {
        let result = Cli::try_parse_from(["pq-diary", "new"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New {
                title,
                body,
                tag,
                template,
            } => {
                assert_eq!(title, None);
                assert_eq!(body, None);
                assert!(tag.is_empty());
                assert_eq!(template, None);
            }
            _ => panic!("Expected Commands::New"),
        }
    }

    /// TC-0037-P02: `new "My Title"` parses the positional title argument.
    #[test]
    fn tc_0037_p02_new_with_title() {
        let result = Cli::try_parse_from(["pq-diary", "new", "My Title"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New {
                title, body, tag, ..
            } => {
                assert_eq!(title, Some("My Title".to_string()));
                assert_eq!(body, None);
                assert!(tag.is_empty());
            }
            _ => panic!("Expected Commands::New"),
        }
    }

    /// TC-0037-P03: `new --body "text"` parses the long body flag.
    #[test]
    fn tc_0037_p03_new_with_long_body_flag() {
        let result = Cli::try_parse_from(["pq-diary", "new", "--body", "Hello World"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New {
                title, body, tag, ..
            } => {
                assert_eq!(title, None);
                assert_eq!(body, Some("Hello World".to_string()));
                assert!(tag.is_empty());
            }
            _ => panic!("Expected Commands::New"),
        }
    }

    /// TC-0037-P04: `new -b "text"` parses the short body flag.
    #[test]
    fn tc_0037_p04_new_with_short_body_flag() {
        let result = Cli::try_parse_from(["pq-diary", "new", "-b", "Short body"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New { body, .. } => {
                assert_eq!(body, Some("Short body".to_string()));
            }
            _ => panic!("Expected Commands::New"),
        }
    }

    /// TC-0037-P05: `-t tag1 --tag tag2` accumulates multiple tags.
    #[test]
    fn tc_0037_p05_new_with_multiple_tags() {
        let result = Cli::try_parse_from(["pq-diary", "new", "-t", "tag1", "--tag", "tag2"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New { tag, .. } => {
                assert_eq!(tag, vec!["tag1".to_string(), "tag2".to_string()]);
            }
            _ => panic!("Expected Commands::New"),
        }
    }

    /// TC-0037-P06: Combined title, body, and tags parse correctly together.
    #[test]
    fn tc_0037_p06_new_combined_args() {
        let result = Cli::try_parse_from([
            "pq-diary",
            "new",
            "Entry Title",
            "-b",
            "body text",
            "-t",
            "work",
        ]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New {
                title, body, tag, ..
            } => {
                assert_eq!(title, Some("Entry Title".to_string()));
                assert_eq!(body, Some("body text".to_string()));
                assert_eq!(tag, vec!["work".to_string()]);
            }
            _ => panic!("Expected Commands::New"),
        }
    }

    // -------------------------------------------------------------------------
    // Commands::Search parsing tests (TASK-0059)
    // -------------------------------------------------------------------------

    /// TC-0059-P01: `search "hello"` parses pattern with default options.
    #[test]
    fn tc_0059_p01_search_basic_pattern() {
        let result = Cli::try_parse_from(["pq-diary", "search", "hello"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Search(args) => {
                assert_eq!(args.pattern, "hello");
                assert_eq!(args.tag, None);
                assert_eq!(args.context, 2);
                assert!(!args.count);
            }
            _ => panic!("Expected Commands::Search"),
        }
    }

    /// TC-0059-P02: `search --tag "日記" "pattern"` parses tag flag.
    #[test]
    fn tc_0059_p02_search_with_tag() {
        let result = Cli::try_parse_from(["pq-diary", "search", "--tag", "日記", "hello"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Search(args) => {
                assert_eq!(args.tag, Some("日記".to_string()));
            }
            _ => panic!("Expected Commands::Search"),
        }
    }

    /// TC-0059-P03: `search --context 0 "pattern"` parses context=0.
    #[test]
    fn tc_0059_p03_search_with_context_0() {
        let result = Cli::try_parse_from(["pq-diary", "search", "--context", "0", "hello"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Search(args) => {
                assert_eq!(args.context, 0);
            }
            _ => panic!("Expected Commands::Search"),
        }
    }

    /// TC-0059-P04: `search --count "pattern"` parses count flag.
    #[test]
    fn tc_0059_p04_search_with_count() {
        let result = Cli::try_parse_from(["pq-diary", "search", "--count", "hello"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Search(args) => {
                assert!(args.count);
            }
            _ => panic!("Expected Commands::Search"),
        }
    }

    /// TC-0059-P05: Combined --tag, --context, --count parse correctly together.
    #[test]
    fn tc_0059_p05_search_combined_flags() {
        let result = Cli::try_parse_from([
            "pq-diary",
            "search",
            "--tag",
            "tech",
            "--context",
            "5",
            "--count",
            r"\d+",
        ]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::Search(args) => {
                assert_eq!(args.pattern, r"\d+");
                assert_eq!(args.tag, Some("tech".to_string()));
                assert_eq!(args.context, 5);
                assert!(args.count);
            }
            _ => panic!("Expected Commands::Search"),
        }
    }
}

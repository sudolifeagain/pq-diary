mod commands;
mod editor;
mod password;

use clap::{Parser, Subcommand};

/// Post-quantum cryptography CLI journal.
#[derive(Debug, Parser)]
#[command(name = "pq-diary", version, about = "Post-quantum cryptography CLI journal")]
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
        /// Entry ID or title
        id: String,
    },

    /// Delete a diary entry
    Delete {
        /// Entry ID or title
        id: String,
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

    /// Search diary entries by keyword
    Search {
        /// Search query string
        query: String,
    },

    /// Show diary statistics
    Stats,

    /// Import entries from an external source
    Import {
        /// Source file or directory path
        source: String,
    },

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
    },

    /// List all available vaults
    List,

    /// Manage access policy for the vault
    Policy,

    /// Delete a vault permanently
    Delete {
        /// Name of the vault to delete
        name: String,
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
    },
}

fn dispatch(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Commands::New { title, body, tag } => {
            commands::cmd_new(cli, title.clone(), body.clone(), tag.clone())
        }
        Commands::Init => not_implemented("init", "Sprint 2"),
        Commands::Vault { subcommand } => match subcommand {
            VaultCommands::Create { .. } => not_implemented("vault create", "Sprint 2"),
            VaultCommands::List => not_implemented("vault list", "Sprint 2"),
            VaultCommands::Policy => not_implemented("vault policy", "Sprint 7"),
            VaultCommands::Delete { .. } => not_implemented("vault delete", "Sprint 2"),
        },
        Commands::List { tag, query, number } => {
            commands::cmd_list(cli, tag.clone(), query.clone(), *number)
        }
        Commands::Show { id } => commands::cmd_show(cli, id.clone()),
        Commands::Edit { .. } => not_implemented("edit", "Sprint 4"),
        Commands::Delete { .. } => not_implemented("delete", "Sprint 4"),
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
        Commands::Today => not_implemented("today", "Sprint 4"),
        Commands::Search { .. } => not_implemented("search", "Sprint 5"),
        Commands::Stats => not_implemented("stats", "Sprint 5"),
        Commands::Import { .. } => not_implemented("import", "Sprint 6"),
        Commands::Template { subcommand } => match subcommand {
            TemplateCommands::Add { .. } => not_implemented("template add", "Sprint 6"),
            TemplateCommands::List => not_implemented("template list", "Sprint 6"),
            TemplateCommands::Show { .. } => not_implemented("template show", "Sprint 6"),
            TemplateCommands::Delete { .. } => not_implemented("template delete", "Sprint 6"),
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
    // Commands::New parsing tests (TASK-0037)
    // -------------------------------------------------------------------------

    /// TC-0037-P01: `new` with no arguments parses with all defaults.
    #[test]
    fn tc_0037_p01_new_no_args_defaults() {
        let result = Cli::try_parse_from(["pq-diary", "new"]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New { title, body, tag } => {
                assert_eq!(title, None);
                assert_eq!(body, None);
                assert!(tag.is_empty());
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
            Commands::New { title, body, tag } => {
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
            Commands::New { title, body, tag } => {
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
        let result =
            Cli::try_parse_from(["pq-diary", "new", "-t", "tag1", "--tag", "tag2"]);
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
            "pq-diary", "new", "Entry Title", "-b", "body text", "-t", "work",
        ]);
        assert!(result.is_ok(), "parse failed: {:?}", result.unwrap_err());
        let cli = result.unwrap();
        match cli.command {
            Commands::New { title, body, tag } => {
                assert_eq!(title, Some("Entry Title".to_string()));
                assert_eq!(body, Some("body text".to_string()));
                assert_eq!(tag, vec!["work".to_string()]);
            }
            _ => panic!("Expected Commands::New"),
        }
    }
}

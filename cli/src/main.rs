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
    New,

    /// List diary entries
    List,

    /// Show a diary entry
    Show {
        /// Entry ID or title
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

fn dispatch(cli: &Cli) -> ! {
    let (cmd_name, sprint) = match &cli.command {
        Commands::Init => ("init", "Sprint 2"),
        Commands::Vault { subcommand } => match subcommand {
            VaultCommands::Create { .. } => ("vault create", "Sprint 2"),
            VaultCommands::List => ("vault list", "Sprint 2"),
            VaultCommands::Policy => ("vault policy", "Sprint 7"),
            VaultCommands::Delete { .. } => ("vault delete", "Sprint 2"),
        },
        Commands::New => ("new", "Sprint 4"),
        Commands::List => ("list", "Sprint 4"),
        Commands::Show { .. } => ("show", "Sprint 4"),
        Commands::Edit { .. } => ("edit", "Sprint 4"),
        Commands::Delete { .. } => ("delete", "Sprint 4"),
        Commands::Sync => ("sync", "Sprint 8"),
        Commands::Export => ("export", "Sprint 5"),
        Commands::ChangePassword => ("change-password", "Sprint 3"),
        Commands::Info { .. } => ("info", "Sprint 2"),
        Commands::GitInit => ("git-init", "Sprint 8"),
        Commands::GitPush => ("git-push", "Sprint 8"),
        Commands::GitPull => ("git-pull", "Sprint 8"),
        Commands::GitSync => ("git-sync", "Sprint 8"),
        Commands::GitStatus => ("git-status", "Sprint 8"),
        Commands::Legacy { subcommand } => match subcommand {
            LegacyCommands::Init => ("legacy init", "Sprint 9"),
            LegacyCommands::Rotate => ("legacy rotate", "Sprint 9"),
            LegacyCommands::Set => ("legacy set", "Sprint 9"),
            LegacyCommands::List => ("legacy list", "Sprint 9"),
        },
        Commands::LegacyAccess => ("legacy-access", "Sprint 9"),
        Commands::Daemon { subcommand } => match subcommand {
            DaemonCommands::Start => ("daemon start", "Sprint 10"),
            DaemonCommands::Stop => ("daemon stop", "Sprint 10"),
            DaemonCommands::Status => ("daemon status", "Sprint 10"),
            DaemonCommands::Lock => ("daemon lock", "Sprint 10"),
        },
        Commands::Today => ("today", "Sprint 4"),
        Commands::Search { .. } => ("search", "Sprint 5"),
        Commands::Stats => ("stats", "Sprint 5"),
        Commands::Import { .. } => ("import", "Sprint 6"),
        Commands::Template { subcommand } => match subcommand {
            TemplateCommands::Add { .. } => ("template add", "Sprint 6"),
            TemplateCommands::List => ("template list", "Sprint 6"),
            TemplateCommands::Show { .. } => ("template show", "Sprint 6"),
            TemplateCommands::Delete { .. } => ("template delete", "Sprint 6"),
        },
    };
    eprintln!("Command '{cmd_name}' is not yet implemented. Planned for {sprint}.");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();
    dispatch(&cli);
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
}

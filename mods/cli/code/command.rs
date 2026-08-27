//! Provider-independent Fortress command registry.
//!
//! Command metadata is core operational data. Parsing process arguments and
//! rendering terminal output remain responsibilities of presentation crates.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use fortress_core::identity::{StableId, StableIdError};

const BUILTIN_COMMANDS: &[CommandDescriptor] = &[
    CommandDescriptor {
        id: "CMD-CORE-HELP",
        name: "help",
        aliases: &["-h", "--help"],
        description: "List available commands or explain one registered command.",
        usage: "fortress help [command]",
    },
    CommandDescriptor {
        id: "CMD-CORE-VERSION",
        name: "version",
        aliases: &["-V", "--version"],
        description: "Print the Fortress CLI implementation version.",
        usage: "fortress --version",
    },
    CommandDescriptor {
        id: "CMD-SNAPSHOT-AUDIT",
        name: "audit",
        aliases: &[],
        description: "Build and evaluate a stabilized repository snapshot.",
        usage: "fortress audit [path] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-CONTRACT-CCG",
        name: "ccg",
        aliases: &[],
        description: "Compile and render the deterministic Contract Coherency Graph.",
        usage: "fortress ccg [path] [--format json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-BEHAVIOR-BFG",
        name: "bfg",
        aliases: &[],
        description: "Compile and render the deterministic Intended Behavioral Flow Graph.",
        usage: "fortress bfg [path] [--format json] [--output path]",
    },
];

/// Discoverable metadata for one registered Fortress command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandDescriptor {
    id: &'static str,
    name: &'static str,
    aliases: &'static [&'static str],
    description: &'static str,
    usage: &'static str,
}

impl CommandDescriptor {
    /// Returns the stable command contract identity.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Returns the canonical command name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns supported aliases, including flag-form entrypoints.
    #[must_use]
    pub const fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }

    /// Returns the human-readable command purpose.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.description
    }

    /// Returns the canonical human-readable invocation.
    #[must_use]
    pub const fn usage(&self) -> &'static str {
        self.usage
    }

    fn matches(&self, value: &str) -> bool {
        self.name == value || self.aliases.contains(&value)
    }
}

/// Read-only registry for the commands genuinely implemented by this build.
#[derive(Clone, Copy, Debug)]
pub struct CommandRegistry {
    commands: &'static [CommandDescriptor],
}

impl CommandRegistry {
    /// Returns the registry of currently implemented built-in commands.
    #[must_use]
    pub const fn builtin() -> Self {
        Self {
            commands: BUILTIN_COMMANDS,
        }
    }

    /// Iterates through commands in canonical discovery order.
    #[must_use]
    pub fn commands(&self) -> impl ExactSizeIterator<Item = &CommandDescriptor> {
        self.commands.iter()
    }

    /// Resolves a canonical command name or registered alias.
    #[must_use]
    pub fn find(&self, value: &str) -> Option<&CommandDescriptor> {
        self.commands.iter().find(|command| command.matches(value))
    }

    /// Validates command identities and discovery keys.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError`] when an ID is invalid or not a command
    /// ID, a canonical name is empty, or a name/alias conflicts with an earlier
    /// registry entry.
    pub fn validate(&self) -> Result<(), CommandRegistryError> {
        for (index, command) in self.commands.iter().enumerate() {
            let identity = StableId::parse(command.id).map_err(|source| {
                CommandRegistryError::InvalidIdentity {
                    id: command.id,
                    source,
                }
            })?;
            if identity.namespace() != "CMD" {
                return Err(CommandRegistryError::NonCommandIdentity(command.id));
            }
            if command.name.is_empty() {
                return Err(CommandRegistryError::EmptyName(command.id));
            }

            for key in std::iter::once(command.name).chain(command.aliases.iter().copied()) {
                if self.commands[..index]
                    .iter()
                    .any(|existing| existing.matches(key))
                {
                    return Err(CommandRegistryError::DuplicateDiscoveryKey(key));
                }
            }
        }
        Ok(())
    }
}

/// Explains why a command registry is not safe for discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandRegistryError {
    /// A command contract ID failed stable identity validation.
    InvalidIdentity {
        /// Invalid registry value.
        id: &'static str,
        /// Stable identity failure.
        source: StableIdError,
    },
    /// A stable identity did not use the `CMD` namespace.
    NonCommandIdentity(&'static str),
    /// A command had no canonical name.
    EmptyName(&'static str),
    /// A canonical name or alias was already registered.
    DuplicateDiscoveryKey(&'static str),
}

impl Display for CommandRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity { id, source } => {
                write!(
                    formatter,
                    "command `{id}` has an invalid identity: {source}"
                )
            }
            Self::NonCommandIdentity(id) => {
                write!(
                    formatter,
                    "command identity `{id}` does not use the CMD namespace"
                )
            }
            Self::EmptyName(id) => write!(formatter, "command `{id}` has an empty name"),
            Self::DuplicateDiscoveryKey(key) => {
                write!(formatter, "command discovery key `{key}` is duplicated")
            }
        }
    }
}

impl Error for CommandRegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidIdentity { source, .. } => Some(source),
            Self::NonCommandIdentity(_) | Self::EmptyName(_) | Self::DuplicateDiscoveryKey(_) => {
                None
            }
        }
    }
}

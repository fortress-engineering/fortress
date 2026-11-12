//! Provider-independent Fortress command registry.
//!
//! Command metadata is core operational data. Parsing process arguments and
//! rendering terminal output remain responsibilities of presentation crates.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use fortress_core::identity::{StableId, StableIdError};

const BUILTIN_COMMANDS: &[CommandDescriptor] = &[
    CommandDescriptor {
        id: "CMD-GOVERNANCE-OVERLAY",
        name: "overlay",
        aliases: &[],
        description: "Evaluate exact proposed source changes and inspect post-write agreement without writing source or granting actual certification.",
        usage: "fortress overlay base --root path; fortress overlay evaluate --root path --request file [--storage-root external-path] [--base-selection file] [--original-state reference] [--export] [--format human|json]; fortress overlay inspect|reconcile --root path --proposal file [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-GOVERNANCE-MIGRATE",
        name: "migrate",
        aliases: &[],
        description: "Preview, explicitly apply, inspect or recover exact-state journaled migration plans through the common Migration Governance engine.",
        usage: "fortress migrate preview --operations file [--root path] [--base-selection file] [--reviewed-intent digest] [--export] [--format human|json]; fortress migrate inspect --plan file|--receipt file; fortress migrate apply --plan file [--root path] [--storage-root path]; fortress migrate recover --plan file --transaction id --direction resume|rollback [--root path] [--storage-root path]",
    },
    CommandDescriptor {
        id: "CMD-PROTECTED-AUTHORITY",
        name: "authority",
        aliases: &[],
        description: "Preview protected authority changes against explicitly selected base policy without granting permission or claiming host enforcement.",
        usage: "fortress authority capture [path]; fortress authority preview --from snapshot --to snapshot --base-selection file [--format human|json]; fortress authority inspect --decision file [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-PORTABLE-BUNDLE",
        name: "bundle",
        aliases: &[],
        description: "Export registered portable evidence or verify it independently offline, without authentication claims.",
        usage: "fortress bundle export [path] --output new-directory --predicate-type URI [--state file|--generation sha256:...|--selection key]; fortress bundle verify bundle --predicate-type URI [--current-state file|--expected-subject digest --expected-context digest --expected-authority digest --expected-profile digest] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-PORTABLE-SARIF",
        name: "sarif",
        aliases: &[],
        description: "Project retained findings and scoped claims into SARIF 2.1.0 with explicit presentation losses.",
        usage: "fortress sarif [path] [--state file|--generation sha256:...|--selection key|--audit file [--declaration file] [--authority file]] [--output new-file]",
    },
    CommandDescriptor {
        id: "CMD-STATE-TRANSITION",
        name: "transition",
        aliases: &[],
        description: "Compare exact subject, intent, authority and governance states without verdict-only causation.",
        usage: "fortress transition --from file|generation:sha256:...|current --to reference [path] [--format human|json] [--limit count] [--cursor token] [--context file]; fortress transition capture [path]",
    },
    CommandDescriptor {
        id: "CMD-GOVERNANCE-STATUS",
        name: "status",
        aliases: &[],
        description: "Inspect selected governance, source freshness and independent result dimensions.",
        usage: "fortress status [path] [--format human|json] [--selection key] [--state path] [--timing]",
    },
    CommandDescriptor {
        id: "CMD-GOVERNANCE-DOCTOR",
        name: "doctor",
        aliases: &[],
        description: "Diagnose inputs, environment, evidence and storage without running or repairing project code.",
        usage: "fortress doctor [path] [--format human|json] [--selection key] [--state path]",
    },
    CommandDescriptor {
        id: "CMD-GOVERNANCE-QUERY",
        name: "query",
        aliases: &[],
        description: "Query immutable Module policy and directed governance relationships.",
        usage: "fortress query modules|policy|dependents|routes|relationships|references [selector] [path] [--selector module] [--target selector] [--limit count] [--cursor token] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-GOVERNANCE-EXPLAIN",
        name: "explain",
        aliases: &[],
        description: "Explain recorded findings, claims, obligations and defeaters with paged evidence.",
        usage: "fortress explain reference [path] [--state path] [--selection key] [--decision receipt] [--limit count] [--cursor token] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-GOVERNANCE-AUTHOR",
        name: "author",
        aliases: &[],
        description: "Preview canonical governance proposals from readable Module selectors and schema guidance.",
        usage: "fortress author module [path] [--target effect-or-capability --disposition ALLOW|DENY] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-GOVERNANCE-SERVE",
        name: "serve",
        aliases: &[],
        description: "Serve the versioned read-only inspection protocol over bounded JSON lines.",
        usage: "fortress serve --stdio [path] [--selection key] [--state path] [--decision receipt] [--proposal file] [--flow-authoring]",
    },
    CommandDescriptor {
        id: "CMD-PROVIDER-EVIDENCE",
        name: "evidence",
        aliases: &[],
        description: "Normalize retained JUnit or SARIF observations without executing project code.",
        usage: "fortress evidence junit|sarif payload [--manifest path] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-APPLICATION-DECLARE",
        name: "declare",
        aliases: &[],
        description: "Render a truthful multidimensional application declaration.",
        usage: "fortress declare [path] [--format json] [--output path] [--evidence-inputs path] [--provider-policy host-path]",
    },
    CommandDescriptor {
        id: "CMD-APPLICATION-ASSESS",
        name: "assess",
        aliases: &[],
        description: "Assess exact selected application profiles without inventing test execution.",
        usage: "fortress assess [path] [--format json] [--output path] [--evidence-inputs path] [--provider-policy host-path]",
    },
    CommandDescriptor {
        id: "CMD-APPLICATION-STATE-VIEW",
        name: "state-view",
        aliases: &[],
        description: "Render a neutral governed, partial, negative, invalid or ungoverned endpoint.",
        usage: "fortress state-view [path] [--format json] [--output path] [--evidence-inputs path] [--provider-policy host-path]",
    },
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
        id: "CMD-FINDING-CHECK",
        name: "check",
        aliases: &[],
        description: "Evaluate progressive finding enforcement without rewriting conformance.",
        usage: "fortress check [path] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-FINDING-LIST",
        name: "findings",
        aliases: &[],
        description: "List current stable finding identities and lifecycle governance.",
        usage: "fortress findings [path] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-FINDING-BASELINE",
        name: "baseline",
        aliases: &[],
        description: "Preview anchored baseline adoption, comparable retirement and retained lifecycle evidence.",
        usage: "fortress baseline capture|create|review|prune [path] [--from state --to state] [--finding ID] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-FINDING-EXCEPTION",
        name: "exceptions",
        aliases: &[],
        description: "Inspect or propose exact finding-specific exception review and retirement.",
        usage: "fortress exceptions list|review|create|retire [exact IDs and review policy] [path] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-REPOSITORY-INIT",
        name: "init",
        aliases: &[],
        description: "Review native or canonical repository onboarding and explicitly apply through shared transactions.",
        usage: "fortress init [path] [--project-id ID --display-name NAME] [--mode native|canonical] [--request path] [--format human|json] [--output path] | fortress init inspect|review|apply|recover [path] --proposal path",
    },
    CommandDescriptor {
        id: "CMD-MODULE-INSPECTION",
        name: "modules",
        aliases: &[],
        description: "Inspect declared Module contracts, logical source bindings, and analysis-only ownership.",
        usage: "fortress modules [path] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-AFFECTED-ANALYSIS",
        name: "affected",
        aliases: &[],
        description: "Explain exact-snapshot semantic invalidation and reusable results.",
        usage: "fortress affected [path] --from snapshot-path [--format human|json] [--output path]",
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
    CommandDescriptor {
        id: "CMD-BEHAVIOR-REALIZED-BFG",
        name: "realized-bfg",
        aliases: &[],
        description: "Compile and render the deterministic Realized Behavioral Flow Graph.",
        usage: "fortress realized-bfg [path] [--format json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-PROGRAM-PSM",
        name: "psm",
        aliases: &[],
        description: "Compile and render the deterministic Program Semantic Model.",
        usage: "fortress psm [path] [--format json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-SEMANTIC-ANALYSIS",
        name: "semantic",
        aliases: &[],
        description: "Compile and render deterministic function-domain analysis.",
        usage: "fortress semantic [path] [--format json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-STATE-EFFECT-ANALYSIS",
        name: "state-effect",
        aliases: &[],
        description: "Compile and render deterministic state and effect analysis.",
        usage: "fortress state-effect [path] [--format json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-SEMANTIC-CONFORMANCE",
        name: "semantic-conformance",
        aliases: &[],
        description: "Evaluate declared Module semantic policy against causal effect evidence.",
        usage: "fortress semantic-conformance [path] [--module ID] [--format human|json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-INFORMATION-FLOW",
        name: "information-flow",
        aliases: &[],
        description: "Compile and render deterministic information-flow analysis.",
        usage: "fortress information-flow [path] [--format human|json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-BEHAVIOR-AUTHOR",
        name: "behavior-author",
        aliases: &[],
        description: "Preview unapplied readable behavioral checkpoint bindings.",
        usage: "fortress behavior-author [path] --feature ID --checkpoint ID=NAME [--return ID] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-FLOW-AUTHOR",
        name: "flow-author",
        aliases: &[],
        description: "Preview a bounded operation source/sink policy using readable names.",
        usage: "fortress flow-author [path] --source NAME --sink NAME --facet ID --level LEVEL --bound LEVEL [--parameter N] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-ENVIRONMENTAL-ANALYSIS",
        name: "environmental",
        aliases: &[],
        description: "Compile and render deterministic environmental analysis.",
        usage: "fortress environmental [path] [--format json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-REFERENCE-RESOLUTION",
        name: "references",
        aliases: &["resolve"],
        description: "Resolve stable Module identities and preview relocation-transparent path churn.",
        usage: "fortress references [path] [--format json] [--output path] [--move Module-ID --to Parent-Module-ID]",
    },
    CommandDescriptor {
        id: "CMD-IDENTITY-MIGRATION",
        name: "migrate-identities",
        aliases: &[],
        description: "Preview or explicitly apply unambiguous legacy semantic identity migrations.",
        usage: "fortress migrate-identities [path] [--apply] [--format human|json]",
    },
    CommandDescriptor {
        id: "CMD-SOURCE-ARTIFACT-MODEL",
        name: "source-artifacts",
        aliases: &[],
        description: "Compile and render the language-neutral Source Artifact Model.",
        usage: "fortress source-artifacts [path] [--format human|json] [--output path]",
    },
    CommandDescriptor {
        id: "CMD-CERTIFICATION-FULL-SNAPSHOT",
        name: "certify",
        aliases: &[],
        description: "Execute local verification and certify the exact source snapshot.",
        usage: "fortress certify [path] [--format human|json] [--evidence-output path] [--certification-output path] [--verified-bfg-output path] [--projection-output-dir path] [--audit-output path]",
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

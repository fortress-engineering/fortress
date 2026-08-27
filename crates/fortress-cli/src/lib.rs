//! Terminal presentation and argument dispatch for the Fortress CLI.
//!
//! This crate renders the provider-independent command registry from
//! `fortress-core`. It registers no placeholder operation and reports an
//! unsupported command with a non-success exit code.

#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, warnings)]

use std::io::{self, Write};

use fortress_core::command::{CommandDescriptor, CommandRegistry};

/// Successful process exit status.
pub const EXIT_SUCCESS: u8 = 0;
/// User invocation or unsupported-command exit status.
pub const EXIT_USAGE: u8 = 2;

/// Runs Fortress CLI dispatch against caller-provided streams.
///
/// The iterator contains arguments after the executable name. Empty input
/// renders top-level help. Unsupported operations are never treated as success.
///
/// # Errors
///
/// Returns an I/O error when writing user-visible output fails.
pub fn run<I, S, O, E>(arguments: I, output: &mut O, error: &mut E) -> io::Result<u8>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    O: Write,
    E: Write,
{
    let registry = CommandRegistry::builtin();
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let Some(first) = arguments.first() else {
        render_top_level_help(&registry, output)?;
        return Ok(EXIT_SUCCESS);
    };

    let Some(command) = registry.find(first) else {
        writeln!(
            error,
            "unsupported command `{first}`; run `fortress help` to list implemented commands"
        )?;
        return Ok(EXIT_USAGE);
    };

    match command.id() {
        "CMD-CORE-HELP" => run_help(&registry, &arguments[1..], output, error),
        "CMD-CORE-VERSION" => run_version(&arguments[1..], output, error),
        _ => {
            writeln!(
                error,
                "registered command `{}` has no CLI executor",
                command.id()
            )?;
            Ok(EXIT_USAGE)
        }
    }
}

fn run_help<O: Write, E: Write>(
    registry: &CommandRegistry,
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    match arguments {
        [] => {
            render_top_level_help(registry, output)?;
            Ok(EXIT_SUCCESS)
        }
        [name] => {
            if let Some(command) = registry.find(name) {
                render_command_help(command, output)?;
                Ok(EXIT_SUCCESS)
            } else {
                writeln!(error, "no implemented command named `{name}`")?;
                Ok(EXIT_USAGE)
            }
        }
        _ => {
            writeln!(error, "usage: fortress help [command]")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn run_version<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    if arguments.is_empty() {
        writeln!(output, "fortress {}", env!("CARGO_PKG_VERSION"))?;
        Ok(EXIT_SUCCESS)
    } else {
        writeln!(error, "usage: fortress --version")?;
        Ok(EXIT_USAGE)
    }
}

fn render_top_level_help<O: Write>(registry: &CommandRegistry, output: &mut O) -> io::Result<()> {
    writeln!(output, "Fortress {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(
        output,
        "Engineering control plane for coherent, auditable software systems."
    )?;
    writeln!(output)?;
    writeln!(output, "USAGE:")?;
    writeln!(output, "    fortress <command>")?;
    writeln!(output, "    fortress --version")?;
    writeln!(output)?;
    writeln!(output, "IMPLEMENTED COMMANDS:")?;
    for command in registry.commands() {
        writeln!(
            output,
            "    {:<10} {}",
            command.name(),
            command.description()
        )?;
    }
    writeln!(output)?;
    writeln!(
        output,
        "Only listed commands are implemented. No certification claim is made."
    )
}

fn render_command_help<O: Write>(command: &CommandDescriptor, output: &mut O) -> io::Result<()> {
    writeln!(output, "{} — {}", command.name(), command.description())?;
    writeln!(output)?;
    writeln!(output, "USAGE:")?;
    writeln!(output, "    {}", command.usage())?;
    if !command.aliases().is_empty() {
        writeln!(output)?;
        writeln!(output, "ALIASES:")?;
        writeln!(output, "    {}", command.aliases().join(", "))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EXIT_SUCCESS, EXIT_USAGE, run};

    /// `T-TF-CLI-0001-R02-001`
    #[test]
    fn no_arguments_render_help() {
        let mut output = Vec::new();
        let mut error = Vec::new();
        let status = run(Vec::<String>::new(), &mut output, &mut error).expect("write succeeds");
        assert_eq!(status, EXIT_SUCCESS);
        assert!(String::from_utf8_lossy(&output).contains("IMPLEMENTED COMMANDS"));
        assert!(error.is_empty());
    }

    /// `T-TF-CLI-0001-R02-002`
    #[test]
    fn unknown_command_is_non_success() {
        let mut output = Vec::new();
        let mut error = Vec::new();
        let status = run(["audit"], &mut output, &mut error).expect("write succeeds");
        assert_eq!(status, EXIT_USAGE);
        assert!(output.is_empty());
        assert!(String::from_utf8_lossy(&error).contains("unsupported command `audit`"));
    }
}

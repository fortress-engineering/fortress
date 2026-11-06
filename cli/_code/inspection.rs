//! Thin command parsing and human/JSON rendering for the shared inspection facade.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use fortress_core::query::{QueryLoadOptions, QueryRequest, load_repository_query};
use serde_json::{Value, json};

/// Executes one read-only inspection command.
pub(super) fn run<O: Write, E: Write>(
    name: &str,
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let parsed = match parse(name, arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(crate::EXIT_USAGE);
        }
    };
    let started = std::time::Instant::now();
    let service = match load_repository_query(&parsed.root, &parsed.options) {
        Ok(service) => service,
        Err(failure) => {
            writeln!(error, "inspection loading failed: {failure}")?;
            return Ok(crate::EXIT_VIOLATION);
        }
    };
    let load_duration = started.elapsed();
    if name == "serve" {
        crate::rpc::serve(
            io::BufReader::new(io::stdin()),
            output,
            &std::sync::Arc::new(service),
        )?;
        return Ok(crate::EXIT_SUCCESS);
    }
    let request = QueryRequest {
        protocol_version: 1,
        request_id: "cli".into(),
        method: name.into(),
        state_ref: None,
        context_ref: None,
        parameters: parsed.parameters,
    };
    let started = std::time::Instant::now();
    let response = service.execute(&request, &AtomicBool::new(false));
    let query_duration = started.elapsed();
    if parsed.json {
        output.write_all(&response.to_canonical_bytes().map_err(io::Error::other)?)?;
        writeln!(output)?;
    } else {
        write!(output, "{}", response.to_human())?;
    }
    if parsed.timing {
        writeln!(
            error,
            "diagnostic timing (uncontrolled host, no certification threshold): cold_load_us={}, warm_query_us={}",
            load_duration.as_micros(),
            query_duration.as_micros()
        )?;
    }
    Ok(if response.error.is_some() {
        crate::EXIT_USAGE
    } else {
        crate::EXIT_SUCCESS
    })
}

struct Parsed {
    root: PathBuf,
    options: QueryLoadOptions,
    parameters: Value,
    json: bool,
    timing: bool,
}

fn parse(name: &str, arguments: &[String]) -> Result<Parsed, String> {
    let mut options = QueryLoadOptions::default();
    let mut parameters = json!({});
    let mut positional = Vec::new();
    let mut json = false;
    let mut timing = false;
    let mut stdio = false;
    let mut page = json!({});
    let mut index = 0;
    let mut seen_options = std::collections::BTreeSet::new();
    while index < arguments.len() {
        let arg = &arguments[index];
        if arg.starts_with('-') && !seen_options.insert(arg) {
            return Err(format!("duplicate inspection option {arg}"));
        }
        match arg.as_str() {
            "--stdio" if name == "serve" => stdio = true,
            "--timing" if name != "serve" => timing = true,
            "--format" | "--selection" | "--state" | "--target" | "--selector"
            | "--disposition" | "--limit" | "--cursor" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                match arg.as_str() {
                    "--format" if matches!(value.as_str(), "json" | "human") && name != "serve" => {
                        json = value == "json";
                    }
                    "--selection" => options.selection_key = Some(value.clone()),
                    "--state" => options.state_path = Some(PathBuf::from(value)),
                    "--target" if matches!(name, "query" | "author") => {
                        parameters["target"] = json!(value);
                    }
                    "--selector" if name == "query" => {
                        parameters["selector"] = json!(value);
                    }
                    "--disposition" if name == "author" => parameters["disposition"] = json!(value),
                    "--limit" if matches!(name, "query" | "explain") => {
                        page["limit"] = json!(
                            value
                                .parse::<usize>()
                                .map_err(|_| "--limit requires an unsigned integer".to_owned())?
                        );
                    }
                    "--cursor" if matches!(name, "query" | "explain") => {
                        page["cursor"] = json!(value);
                    }
                    _ => return Err(format!("unsupported {arg} value or command combination")),
                }
            }
            value if value.starts_with('-') => {
                return Err(format!("unsupported inspection option {value}"));
            }
            _ => positional.push(arg.clone()),
        }
        index += 1;
    }
    if name == "serve" && !stdio {
        return Err("serve requires --stdio".into());
    }
    let parameters = finish_parameters(name, &mut positional, parameters, page)?;
    if positional.len() > 1 {
        return Err("only one repository path is accepted".into());
    }
    let root = PathBuf::from(positional.pop().unwrap_or_else(|| ".".into()))
        .canonicalize()
        .map_err(|failure| failure.to_string())?;
    Ok(Parsed {
        root,
        options,
        parameters,
        json,
        timing,
    })
}

fn finish_parameters(
    name: &str,
    positional: &mut Vec<String>,
    mut parameters: Value,
    page: Value,
) -> Result<Value, String> {
    if name == "query" {
        if positional.is_empty() {
            return Err(
                "query requires modules|policy|dependents|routes|relationships|references".into(),
            );
        }
        parameters["kind"] = json!(positional.remove(0));
        if parameters["kind"] != "modules" && parameters.get("selector").is_none() {
            if positional.is_empty() {
                return Err("query requires a Module selector".into());
            }
            parameters["selector"] = json!(positional.remove(0));
        }
        parameters["page"] = page;
    } else if matches!(name, "explain" | "author") {
        if positional.is_empty() {
            return Err(format!(
                "{name} requires an exact reference or readable Module selector"
            ));
        }
        parameters[if name == "author" {
            "module"
        } else {
            "selector"
        }] = json!(positional.remove(0));
        if name == "explain" {
            parameters["page"] = page;
        }
    }
    Ok(parameters)
}

//! Explicit source preparation followed by the shared read-only authoring facade.
use fortress_core::query::{QueryInput, QueryRequest, QueryService};
use serde_json::json;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

pub(super) fn run<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    match execute(args, output) {
        Ok(()) => Ok(crate::EXIT_SUCCESS),
        Err(reason) => {
            writeln!(error, "flow authoring failed: {reason}")?;
            Ok(crate::EXIT_USAGE)
        }
    }
}

fn execute<O: Write>(args: &[String], output: &mut O) -> Result<(), String> {
    if args == ["--schema"] {
        return output
            .write_all(fortress_core::information_flow::information_flow_policy_schema().as_bytes())
            .map_err(|e| e.to_string());
    }
    let mut root = PathBuf::from(".");
    let mut path_seen = false;
    let mut as_json = false;
    let mut parameters = json!({});
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') && !seen.insert(arg) {
            return Err(format!("duplicate option {arg}"));
        }
        match arg.as_str() {
            "--source" | "--sink" | "--facet" | "--level" | "--bound" | "--parameter"
            | "--format" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                match arg.as_str() {
                    "--format" => {
                        as_json = match value.as_str() {
                            "json" => true,
                            "human" => false,
                            _ => return Err("format must be json or human".into()),
                        };
                    }
                    "--parameter" => {
                        parameters["parameter"] =
                            json!(value.parse::<u16>().map_err(|e| e.to_string())?);
                    }
                    _ => parameters[arg.trim_start_matches('-')] = json!(value),
                }
            }
            value if !value.starts_with('-') && !path_seen => {
                root = value.into();
                path_seen = true;
            }
            _ => return Err("unsupported flow-author argument".into()),
        }
        i += 1;
    }
    // Decode before preparation, so malformed proposals do not start analysis.
    let _: fortress_core::information_flow::FlowAuthorParameters =
        serde_json::from_value(parameters.clone()).map_err(|e| e.to_string())?;
    let (psm, policy, source_ref) = fortress_core::audit::prepare_repository_flow_authoring(&root)
        .map_err(|e| e.to_string())?;
    let service = QueryService::new(QueryInput::empty(source_ref.clone()))
        .map_err(|e| e.to_string())?
        .with_flow_context(&source_ref, psm, policy)
        .map_err(|e| e.to_string())?;
    let response = service.execute(
        &QueryRequest {
            protocol_version: 3,
            request_id: "cli".into(),
            method: "flow_author".into(),
            state_ref: None,
            context_ref: None,
            parameters,
        },
        &AtomicBool::new(false),
    );
    if let Some(e) = &response.error {
        return Err(e.to_string());
    }
    if as_json {
        output
            .write_all(&response.to_canonical_bytes().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        writeln!(output).map_err(|e| e.to_string())?;
    } else {
        write!(output, "{}", response.to_human()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

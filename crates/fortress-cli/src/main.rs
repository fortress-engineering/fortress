//! Native `fortress` executable entrypoint.

#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, warnings)]

use std::env;
use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut output = io::stdout().lock();
    let mut error = io::stderr().lock();
    match fortress_cli::run(env::args().skip(1), &mut output, &mut error) {
        Ok(status) => ExitCode::from(status),
        Err(write_error) => {
            eprintln!("fortress could not write command output: {write_error}");
            ExitCode::FAILURE
        }
    }
}

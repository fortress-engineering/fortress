//! Canonical classification from resolved operation identity to direct effects.

use crate::semantic_analysis::FunctionEffect;

/// A classification grounded in one stable external operation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OperationEffectClassification {
    /// The operation has one or more supported operational effects.
    Supported(Vec<FunctionEffect>),
    /// The operation is known not to cross an effect boundary modeled here.
    NoOperationalEffect,
    /// The operation is externally identified but outside the supported classifier table.
    Unsupported,
}

/// Classifies one exact semantic operation identity.
///
/// The caller supplies identity established by Program Semantics. Source spelling alone
/// never enters this classifier.
#[allow(clippy::too_many_lines)]
pub(super) fn classify_operation(operation: &str) -> OperationEffectClassification {
    use FunctionEffect::{
        EnvironmentRead, EnvironmentWrite, FilesystemRead, FilesystemWrite, MayPanic,
        NetworkConnect, NetworkIo, NetworkListen, ProcessSpawn, RandomRead, TimeMonotonicRead,
        TimeWallRead, UnsafeExecution,
    };

    let effects = if operation == "rust_method::std::fs::OpenOptions::open[read]" {
        vec![FilesystemRead]
    } else if operation == "rust_method::std::fs::OpenOptions::open[write]" {
        vec![FilesystemWrite]
    } else if operation == "rust_method::std::fs::OpenOptions::open[read_write]" {
        vec![FilesystemRead, FilesystemWrite]
    } else if matches!(
        operation,
        "std::fs::read"
            | "std::fs::read_dir"
            | "std::fs::read_link"
            | "std::fs::read_to_string"
            | "std::fs::metadata"
            | "std::fs::symlink_metadata"
            | "std::fs::canonicalize"
            | "std::fs::File::open"
            | "rust_method::std::fs::File::read"
            | "rust_method::std::fs::File::read_exact"
            | "rust_method::std::fs::File::read_to_end"
            | "rust_method::std::fs::File::read_to_string"
    ) {
        vec![FilesystemRead]
    } else if matches!(
        operation,
        "std::fs::write"
            | "std::fs::create_dir"
            | "std::fs::create_dir_all"
            | "std::fs::hard_link"
            | "std::fs::remove_dir"
            | "std::fs::remove_dir_all"
            | "std::fs::remove_file"
            | "std::fs::rename"
            | "std::fs::set_permissions"
            | "std::fs::File::create"
            | "std::fs::File::create_new"
            | "rust_method::std::fs::File::write"
            | "rust_method::std::fs::File::write_all"
            | "rust_method::std::fs::File::flush"
            | "rust_method::std::fs::File::set_len"
            | "rust_method::std::fs::File::set_permissions"
            | "rust_method::std::fs::File::sync_all"
            | "rust_method::std::fs::File::sync_data"
    ) {
        vec![FilesystemWrite]
    } else if operation == "std::fs::copy" {
        vec![FilesystemRead, FilesystemWrite]
    } else if matches!(
        operation,
        "std::net::TcpStream::connect" | "std::net::TcpStream::connect_timeout"
    ) {
        vec![NetworkConnect]
    } else if matches!(
        operation,
        "std::net::TcpListener::bind"
            | "rust_method::std::net::TcpListener::accept"
            | "rust_method::std::net::TcpListener::incoming"
    ) {
        vec![NetworkListen]
    } else if matches!(
        operation,
        "rust_method::std::net::TcpStream::read"
            | "rust_method::std::net::TcpStream::read_exact"
            | "rust_method::std::net::TcpStream::read_to_end"
            | "rust_method::std::net::TcpStream::read_to_string"
            | "rust_method::std::net::TcpStream::write"
            | "rust_method::std::net::TcpStream::write_all"
            | "rust_method::std::net::TcpStream::flush"
            | "rust_method::std::net::UdpSocket::recv"
            | "rust_method::std::net::UdpSocket::recv_from"
            | "rust_method::std::net::UdpSocket::send"
            | "rust_method::std::net::UdpSocket::send_to"
    ) {
        vec![NetworkIo]
    } else if matches!(
        operation,
        "rust_method::std::process::Command::spawn"
            | "rust_method::std::process::Command::status"
            | "rust_method::std::process::Command::output"
            | "std::process::Command::spawn"
            | "std::process::Command::status"
            | "std::process::Command::output"
    ) {
        vec![ProcessSpawn]
    } else if matches!(
        operation,
        "std::env::args"
            | "std::env::args_os"
            | "std::env::current_dir"
            | "std::env::current_exe"
            | "std::env::home_dir"
            | "std::env::temp_dir"
            | "std::env::var"
            | "std::env::var_os"
            | "std::env::vars"
            | "std::env::vars_os"
    ) {
        vec![EnvironmentRead]
    } else if matches!(
        operation,
        "std::env::remove_var" | "std::env::set_current_dir" | "std::env::set_var"
    ) {
        vec![EnvironmentWrite]
    } else if matches!(
        operation,
        "std::time::SystemTime::now" | "rust_method::std::time::SystemTime::elapsed"
    ) {
        vec![TimeWallRead]
    } else if matches!(
        operation,
        "std::time::Instant::now" | "rust_method::std::time::Instant::elapsed"
    ) {
        vec![TimeMonotonicRead]
    } else if matches!(
        operation,
        "getrandom::fill"
            | "getrandom::getrandom"
            | "getrandom::u32"
            | "getrandom::u64"
            | "rand::random"
    ) {
        vec![RandomRead]
    } else if matches!(
        operation,
        "std::panic::panic_any"
            | "std::panic::resume_unwind"
            | "core::panicking::panic"
            | "rust_method::Option::expect"
            | "rust_method::Option::unwrap"
            | "rust_method::Result::expect"
            | "rust_method::Result::unwrap"
            | "rust_method::Result::unwrap_err"
    ) {
        vec![MayPanic]
    } else if matches!(
        operation,
        "rust_method::Option::unwrap_unchecked"
            | "rust_method::Result::unwrap_unchecked"
            | "rust_method::Result::unwrap_err_unchecked"
    ) {
        vec![UnsafeExecution]
    } else if matches!(
        operation,
        "std::process::Command::new"
            | "rust_type::Command::new"
            | "std::fs::OpenOptions::new"
            | "rust_method::std::process::Command::arg"
            | "rust_method::std::process::Command::args"
            | "rust_method::std::process::Command::current_dir"
            | "rust_method::std::process::Command::env"
            | "rust_method::std::process::Command::env_clear"
            | "rust_method::std::process::Command::env_remove"
            | "rust_method::std::process::Command::stdin"
            | "rust_method::std::process::Command::stdout"
            | "rust_method::std::process::Command::stderr"
            | "rust_method::std::process::Command::uid"
            | "rust_method::std::process::Command::gid"
            | "rust_method::std::fs::OpenOptions::read"
            | "rust_method::std::fs::OpenOptions::write"
            | "rust_method::std::fs::OpenOptions::append"
            | "rust_method::std::fs::OpenOptions::truncate"
            | "rust_method::std::fs::OpenOptions::create"
            | "rust_method::std::fs::OpenOptions::create_new"
            | "rust_method::std::fs::OpenOptions::custom_flags"
            | "rust_method::std::fs::OpenOptions::mode"
            | "rust_method::std::fs::OpenOptions::access_mode"
            | "rust_method::std::fs::OpenOptions::share_mode"
            | "rust_method::std::fs::OpenOptions::attributes"
            | "rust_method::std::fs::OpenOptions::security_qos_flags"
            | "rust_prelude::Box"
            | "rust_prelude::None"
            | "rust_prelude::Ok"
            | "rust_prelude::Some"
            | "rust_prelude::Err"
    ) {
        return OperationEffectClassification::NoOperationalEffect;
    } else {
        return OperationEffectClassification::Unsupported;
    };
    OperationEffectClassification::Supported(effects)
}

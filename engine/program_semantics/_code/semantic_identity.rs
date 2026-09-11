//! Versioned Rust semantic and operation-site identity.

use std::collections::BTreeMap;

use proc_macro2::{Spacing, TokenStream, TokenTree};
use quote::ToTokens;
use serde::Serialize;
use sha2::{Digest, Sha256};
use syn::{FnArg, GenericParam, Generics, ReturnType, Signature, TypeParamBound};

use super::ExecutableSymbolKind;

/// Current Rust executable identity algorithm.
pub const RUST_SYMBOL_IDENTITY_ALGORITHM: &str = "fortress.rust.symbol";
/// Current Rust executable identity algorithm version.
pub const RUST_SYMBOL_IDENTITY_VERSION: u16 = 2;
/// Current Rust operation-site identity algorithm.
pub const RUST_OPERATION_SITE_IDENTITY_ALGORITHM: &str = "fortress.rust.operation_site";
/// Current Rust operation-site identity algorithm version.
pub const RUST_OPERATION_SITE_IDENTITY_VERSION: u16 = 1;

#[derive(Serialize)]
struct RustSymbolIdentityV2<'a> {
    language: &'static str,
    package: &'a str,
    crate_name: &'a str,
    namespace: &'a [String],
    kind: ExecutableSymbolKind,
    owner_type: Option<String>,
    owner_trait: Option<String>,
    name: &'a str,
    receiver: Option<ReceiverIdentity>,
    parameter_types: Vec<String>,
    return_type: String,
    surrounding_generics: Vec<GenericIdentity>,
    item_generics: Vec<GenericIdentity>,
    surrounding_where_predicates: Vec<String>,
    item_where_predicates: Vec<String>,
    is_async: SemanticFlag,
    is_unsafe: SemanticFlag,
    is_const: SemanticFlag,
    extern_declared: SemanticFlag,
    abi: Option<String>,
    variadic: SemanticFlag,
}

#[derive(Serialize)]
#[serde(transparent)]
struct SemanticFlag(bool);

#[derive(Serialize)]
struct LegacyRustSymbolIdentity<'a> {
    language: &'static str,
    package: &'a str,
    crate_name: &'a str,
    namespace: &'a [String],
    owner_type: &'a Option<String>,
    owner_trait: &'a Option<String>,
    name: String,
    signature: String,
}

#[derive(Serialize)]
struct ReceiverIdentity {
    by_reference: bool,
    mutable: bool,
    lifetime: Option<String>,
    explicit_type: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum GenericIdentity {
    Type {
        bounds: Vec<String>,
        default: Option<String>,
    },
    Lifetime {
        bounds: Vec<String>,
    },
    Const {
        value_type: String,
        default: Option<String>,
    },
}

#[derive(Default)]
struct AlphaNames {
    identifiers: BTreeMap<String, String>,
    lifetimes: BTreeMap<String, String>,
}

impl AlphaNames {
    fn from_generics(surrounding: Option<&Generics>, item: &Generics) -> Self {
        let mut names = Self::default();
        for generics in surrounding.into_iter().chain(std::iter::once(item)) {
            for parameter in &generics.params {
                match parameter {
                    GenericParam::Type(value) => {
                        let index = names
                            .identifiers
                            .values()
                            .filter(|value| value.starts_with("type#"))
                            .count();
                        names
                            .identifiers
                            .insert(value.ident.to_string(), format!("type#{index}"));
                    }
                    GenericParam::Const(value) => {
                        let index = names
                            .identifiers
                            .values()
                            .filter(|value| value.starts_with("const#"))
                            .count();
                        names
                            .identifiers
                            .insert(value.ident.to_string(), format!("const#{index}"));
                    }
                    GenericParam::Lifetime(value) => {
                        let index = names.lifetimes.len();
                        names.lifetimes.insert(
                            value.lifetime.ident.to_string(),
                            format!("lifetime#{index}"),
                        );
                    }
                }
            }
        }
        names
    }
}

/// Inputs needed to derive current and legacy executable identities.
#[derive(Clone, Copy)]
pub(crate) struct RustSymbolIdentityInput<'a> {
    pub(crate) package: &'a str,
    pub(crate) crate_name: &'a str,
    pub(crate) namespace: &'a [String],
    pub(crate) kind: ExecutableSymbolKind,
    pub(crate) owner_type: &'a Option<String>,
    pub(crate) owner_trait: &'a Option<String>,
    pub(crate) signature: &'a Signature,
    pub(crate) surrounding_generics: Option<&'a Generics>,
}

/// Derives the current versioned Rust symbol ID and its exact legacy alias.
pub(crate) fn rust_symbol_ids(input: RustSymbolIdentityInput<'_>) -> (String, String) {
    let alpha = AlphaNames::from_generics(input.surrounding_generics, &input.signature.generics);
    let name = input.signature.ident.to_string();
    let parameter_types = input
        .signature
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            FnArg::Typed(value) => Some(normalize_tokens(&value.ty, &alpha)),
            FnArg::Receiver(_) => None,
        })
        .collect();
    let receiver = input.signature.receiver().map(|value| ReceiverIdentity {
        by_reference: value.reference.is_some(),
        mutable: value.mutability.is_some(),
        lifetime: value.reference.as_ref().and_then(|(_, lifetime)| {
            lifetime
                .as_ref()
                .map(|lifetime| normalize_tokens(lifetime, &alpha))
        }),
        explicit_type: value
            .colon_token
            .is_some()
            .then(|| normalize_tokens(&value.ty, &alpha)),
    });
    let return_type = match &input.signature.output {
        ReturnType::Default => "unit".into(),
        ReturnType::Type(_, value) => normalize_tokens(value, &alpha),
    };
    let current = RustSymbolIdentityV2 {
        language: "rust",
        package: input.package,
        crate_name: input.crate_name,
        namespace: input.namespace,
        kind: input.kind,
        owner_type: input
            .owner_type
            .as_deref()
            .map(|value| normalize_token_string(value, &alpha)),
        owner_trait: input
            .owner_trait
            .as_deref()
            .map(|value| normalize_token_string(value, &alpha)),
        name: &name,
        receiver,
        parameter_types,
        return_type,
        surrounding_generics: input
            .surrounding_generics
            .map_or_else(Vec::new, |value| normalize_generics(value, &alpha)),
        item_generics: normalize_generics(&input.signature.generics, &alpha),
        surrounding_where_predicates: input
            .surrounding_generics
            .map_or_else(Vec::new, |value| normalize_where(value, &alpha)),
        item_where_predicates: normalize_where(&input.signature.generics, &alpha),
        is_async: SemanticFlag(input.signature.asyncness.is_some()),
        is_unsafe: SemanticFlag(input.signature.unsafety.is_some()),
        is_const: SemanticFlag(input.signature.constness.is_some()),
        extern_declared: SemanticFlag(input.signature.abi.is_some()),
        abi: input
            .signature
            .abi
            .as_ref()
            .and_then(|value| value.name.as_ref().map(syn::LitStr::value)),
        variadic: SemanticFlag(input.signature.variadic.is_some()),
    };
    let legacy = LegacyRustSymbolIdentity {
        language: "rust",
        package: input.package,
        crate_name: input.crate_name,
        namespace: input.namespace,
        owner_type: input.owner_type,
        owner_trait: input.owner_trait,
        name: input.signature.ident.to_string(),
        signature: input.signature.to_token_stream().to_string(),
    };
    (
        hashed_id("rust_symbol:v2", &current),
        hashed_id("rust_symbol", &legacy),
    )
}

/// Derives a location-independent identity for one operation occurrence.
#[must_use]
pub fn rust_operation_site_id(
    containing_symbol: &str,
    operation_kind: &str,
    operation: &str,
    same_operation_ordinal: usize,
) -> String {
    hashed_id(
        "rust_operation_site:v1",
        &(
            containing_symbol,
            operation_kind,
            operation,
            same_operation_ordinal,
        ),
    )
}

fn normalize_generics(generics: &Generics, alpha: &AlphaNames) -> Vec<GenericIdentity> {
    generics
        .params
        .iter()
        .map(|parameter| match parameter {
            GenericParam::Type(value) => GenericIdentity::Type {
                bounds: normalize_bounds(&value.bounds, alpha),
                default: value
                    .default
                    .as_ref()
                    .map(|default| normalize_tokens(default, alpha)),
            },
            GenericParam::Lifetime(value) => GenericIdentity::Lifetime {
                bounds: value
                    .bounds
                    .iter()
                    .map(|bound| normalize_tokens(bound, alpha))
                    .collect(),
            },
            GenericParam::Const(value) => GenericIdentity::Const {
                value_type: normalize_tokens(&value.ty, alpha),
                default: value
                    .default
                    .as_ref()
                    .map(|default| normalize_tokens(default, alpha)),
            },
        })
        .collect()
}

fn normalize_bounds(
    bounds: &syn::punctuated::Punctuated<TypeParamBound, syn::token::Plus>,
    alpha: &AlphaNames,
) -> Vec<String> {
    let mut values = bounds
        .iter()
        .map(|bound| normalize_tokens(bound, alpha))
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn normalize_where(generics: &Generics, alpha: &AlphaNames) -> Vec<String> {
    let mut predicates = generics
        .where_clause
        .iter()
        .flat_map(|clause| clause.predicates.iter())
        .map(|predicate| normalize_tokens(predicate, alpha))
        .collect::<Vec<_>>();
    predicates.sort();
    predicates
}

fn normalize_token_string(value: &str, alpha: &AlphaNames) -> String {
    value.parse::<TokenStream>().map_or_else(
        |_| format!("unsupported:{value}"),
        |tokens| normalize_stream(tokens, alpha),
    )
}

fn normalize_tokens(value: &impl ToTokens, alpha: &AlphaNames) -> String {
    normalize_stream(value.to_token_stream(), alpha)
}

fn normalize_stream(stream: TokenStream, alpha: &AlphaNames) -> String {
    let mut result = String::new();
    let mut tokens = stream.into_iter().peekable();
    while let Some(token) = tokens.next() {
        match token {
            TokenTree::Group(group) => {
                let delimiters = match group.delimiter() {
                    proc_macro2::Delimiter::Parenthesis => ("(", ")"),
                    proc_macro2::Delimiter::Brace => ("{", "}"),
                    proc_macro2::Delimiter::Bracket => ("[", "]"),
                    proc_macro2::Delimiter::None => ("<none>", "</none>"),
                };
                result.push_str(delimiters.0);
                result.push_str(&normalize_stream(group.stream(), alpha));
                result.push_str(delimiters.1);
            }
            TokenTree::Punct(punctuation)
                if punctuation.as_char() == '\''
                    && matches!(tokens.peek(), Some(TokenTree::Ident(_))) =>
            {
                let Some(TokenTree::Ident(identifier)) = tokens.next() else {
                    unreachable!("peeked lifetime identifier")
                };
                result.push_str("lifetime(");
                result.push_str(
                    alpha
                        .lifetimes
                        .get(&identifier.to_string())
                        .map_or_else(|| identifier.to_string(), Clone::clone)
                        .as_str(),
                );
                result.push(')');
            }
            TokenTree::Punct(punctuation) => {
                result.push_str("punct(");
                result.push(punctuation.as_char());
                result.push(':');
                result.push_str(match punctuation.spacing() {
                    Spacing::Alone => "alone",
                    Spacing::Joint => "joint",
                });
                result.push(')');
            }
            TokenTree::Ident(identifier) => {
                result.push_str("ident(");
                result.push_str(
                    alpha
                        .identifiers
                        .get(&identifier.to_string())
                        .map_or_else(|| identifier.to_string(), Clone::clone)
                        .as_str(),
                );
                result.push(')');
            }
            TokenTree::Literal(literal) => {
                result.push_str("literal(");
                result.push_str(&literal.to_string());
                result.push(')');
            }
        }
        result.push('\u{1f}');
    }
    result
}

fn hashed_id(prefix: &str, value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).expect("semantic identity material is serializable");
    format!("{prefix}:sha256:{:x}", Sha256::digest(bytes))
}

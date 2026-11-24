//! Test-naming observations derived exclusively from admitted Python lexical facts.

use serde::Serialize;

use super::{
    ConstructKind, LimitationCode, OpaqueScope, PythonLexicalObservation, ScopeKind, Span,
};

#[derive(Serialize)]
pub(crate) struct PythonTestDeclarations {
    declarations: Vec<TestDeclaration>,
    barriers: Vec<TestBarrier>,
}

#[derive(Serialize)]
struct TestDeclaration {
    scope_id: String,
    name: String,
    kind: DeclarationKind,
    placement: DeclarationPlacement,
    span: Span,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DeclarationKind {
    Function,
    AsyncFunction,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DeclarationPlacement {
    ModuleBody,
    ConditionalModuleScope,
}

#[derive(Serialize)]
struct TestBarrier {
    kind: BarrierKind,
    span: Span,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum BarrierKind {
    UnmodeledModuleFunctionHeader,
    UnmodeledModuleClass,
    ModuleTestNameRebinding,
    ModuleTestNameImport,
}

impl PythonLexicalObservation {
    pub(crate) fn test_declarations(&self) -> PythonTestDeclarations {
        let mut projection = PythonTestDeclarations {
            declarations: Vec::new(),
            barriers: Vec::new(),
        };
        let Some(facts) = &self.report.observations else {
            return projection;
        };
        for scope in &facts.scopes {
            if scope.parent.as_deref() != Some("s0") || !test_name(&scope.name) {
                continue;
            }
            if let Some(span) = scope.span {
                let kind = match scope.kind {
                    ScopeKind::FunctionDef => DeclarationKind::Function,
                    ScopeKind::AsyncFunctionDef => DeclarationKind::AsyncFunction,
                    ScopeKind::Module => continue,
                };
                projection.declarations.push(TestDeclaration {
                    scope_id: scope.id.clone(),
                    name: scope.name.clone(),
                    kind,
                    placement: if span.1 == 0 {
                        DeclarationPlacement::ModuleBody
                    } else {
                        DeclarationPlacement::ConditionalModuleScope
                    },
                    span,
                });
            }
        }
        for item in facts.limitations.iter().filter(|item| item.scope == "s0") {
            let kind = match (item.code, item.kind) {
                (LimitationCode::UnmodeledFunctionScopeOrHeader, _) => {
                    BarrierKind::UnmodeledModuleFunctionHeader
                }
                (LimitationCode::UnmodeledScopeForm, Some(OpaqueScope::ClassDef)) => {
                    BarrierKind::UnmodeledModuleClass
                }
                _ => continue,
            };
            projection.barriers.push(TestBarrier {
                kind,
                span: item.span,
            });
        }
        for item in facts.constructs.iter().filter(|item| {
            item.scope == "s0"
                && item.kind == ConstructKind::NameStore
                && item.spelling.as_deref().is_some_and(test_name)
        }) {
            projection.barriers.push(TestBarrier {
                kind: BarrierKind::ModuleTestNameRebinding,
                span: item.span,
            });
        }
        for item in facts.imports.iter().filter(|item| {
            item.scope == "s0"
                && item
                    .names
                    .iter()
                    .any(|(name, alias)| name == "*" || test_name(alias.as_deref().unwrap_or(name)))
        }) {
            projection.barriers.push(TestBarrier {
                kind: BarrierKind::ModuleTestNameImport,
                span: item.span,
            });
        }
        projection.declarations.sort_by_key(|row| row.span);
        projection.barriers.sort_by_key(|row| (row.span, row.kind));
        projection.barriers.dedup_by_key(|row| (row.span, row.kind));
        projection
    }
}

fn test_name(name: &str) -> bool {
    name.starts_with("test")
}

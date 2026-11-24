//! Exact linkage from an admitted Go module declaration to a scalar body.

use super::super::body_observation::LinkedBody;
use super::{
    Context, ExactClosedPackage, GoCollectorPin, GoModuleRequest, GoNativeModuleObservation,
    GoObservationError, GoRequest, MAX_WIRE, Request, RequestFile, STANDARD, SourceIdentity,
    SourceText, Span, Status, digest, seal_go_request,
};
use base64::Engine as _;

use std::collections::BTreeMap;

use crate::program_semantics::canonical_fact_id;
use crate::program_semantics::go_observation::{DeclarationKind, Implementation};
use crate::program_semantics::native_body::{NativeBodyLanguage, NativeScalarBody};
use crate::program_semantics::native_callable::{
    NativeCallableLimitation as Limit, NativeCallableOutcome, VerifiedCallableLink,
};

impl GoModuleRequest<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn link_callable<T>(
        &self,
        original: ExactClosedPackage<'_>,
        receipt: &GoNativeModuleObservation,
        body_pin: &GoCollectorPin<'_>,
        function: &str,
        manifest: &str,
        launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
        call_analysis: (
            bool,
            impl FnOnce(&NativeScalarBody, &BTreeMap<&str, Option<&NativeScalarBody>>) -> Option<T>,
        ),
    ) -> Result<(NativeCallableOutcome, Option<T>), GoObservationError> {
        if receipt.binding_sha256 != self.base.binding_sha256
            || receipt.observation.request_sha256 != self.base.request_sha256
            || receipt.provenance["source_view_sha256"].as_str() != Some(original.source.digest())
            || self.base.authority_sha256 != original.authority_digest
            || self.base.context.go_version != original.go_version
            || self.base.context.target_os != original.target_os
            || self.base.context.target_arch != original.target_arch
            || !original.actual
        {
            return Err(GoObservationError::InvalidResponse);
        }
        if receipt.observation.status != Status::Observed {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::UnsupportedScope),
                None,
            ));
        }
        if body_pin.go_toolchain != self.base.pin.go_toolchain
            || !digest(body_pin.executable_sha256)
            || !digest(body_pin.supervisor_context_sha256)
        {
            return Err(GoObservationError::InvalidTrustedBinding);
        }
        if function == "init"
            || function == "_"
            || !super::display_name(function)
            || self.comparison.is_some()
            || !self.build_context.custom_tags.is_empty()
            || self
                .build_context
                .tool_tags
                .iter()
                .map(String::as_str)
                .ne(["amd64.v1"])
        {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::UnsupportedScope),
                None,
            ));
        }
        let [package] = receipt.observation.observed_packages.as_slice() else {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::UnsupportedScope),
                None,
            ));
        };
        if package.import_path != original.package_path || !package.imports.is_empty() {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::UnsupportedScope),
                None,
            ));
        }

        let mut matches = package.declarations.iter().filter(|declaration| {
            declaration.name == function && declaration.kind == DeclarationKind::Function
        });
        let Some(declaration) = matches.next() else {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::MissingSubject),
                None,
            ));
        };
        if matches.next().is_some() {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::AmbiguousSubject),
                None,
            ));
        }
        if declaration.implementation != Implementation::SourceBody {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::BodyUnavailable),
                None,
            ));
        }

        let request = self.body_request(original, receipt, body_pin)?;
        let bytes = launch(request.request_bytes())?;
        let (call_returns, analyze) = call_analysis;
        let (bodies, observed) = if call_returns {
            let bodies = request.verify_bound_bodies(body_pin, manifest, &bytes)?;
            let observed = if let Some(body) = bodies.call_body_at(function, &declaration.span) {
                analyze(body, &bodies.call_targets()?)
            } else {
                None
            };
            (bodies, observed)
        } else {
            (request.verify_bodies(body_pin, manifest, &bytes)?, None)
        };
        let linked = match bodies.into_callable(function, &declaration.span) {
            Ok(linked) => linked,
            Err(limit) => return Ok((NativeCallableOutcome::Unavailable(limit), None)),
        };
        let subject =
            link_observed_callable(original, receipt, function, &declaration.span, linked)?;
        Ok((subject, observed))
    }

    fn body_request<'a>(
        &'a self,
        original: ExactClosedPackage<'a>,
        receipt: &GoNativeModuleObservation,
        pin: &'a GoCollectorPin<'a>,
    ) -> Result<GoRequest<'a>, GoObservationError> {
        use super::Disposition;
        let mut inventory = Vec::new();
        let mut files = std::collections::BTreeMap::new();
        let mut request_files = Vec::new();
        for row in &receipt.observation.selection {
            if row.disposition != Disposition::SelectedGoSource {
                continue;
            }
            // Use the keys and bytes of the original immutable view, not
            // independently chosen paths or deserialized bytes from either tool.
            let (path, bytes) = original
                .source
                .files()
                .get_key_value(&row.path)
                .ok_or(GoObservationError::InvalidResponse)?;
            if self.owners.get(path.as_str()).map(String::as_str) != Some(original.package_path) {
                return Err(GoObservationError::InvalidResponse);
            }
            let sha256 = super::sha256(bytes);
            if sha256 != row.sha256 {
                return Err(GoObservationError::InvalidResponse);
            }
            files.insert(path.as_str(), SourceText::new(bytes)?);
            inventory.push(SourceIdentity {
                path: path.clone(),
                sha256: sha256.clone(),
            });
            request_files.push(RequestFile {
                path,
                sha256,
                source_base64: STANDARD.encode(bytes),
            });
        }
        let context = Context {
            package_path: original.package_path.into(),
            go_version: original.go_version.into(),
            target_os: original.target_os.into(),
            target_arch: original.target_arch.into(),
            source_inventory: inventory,
        };
        let request = Request {
            schema_version: 1,
            package_path: original.package_path,
            go_version: original.go_version,
            target_os: original.target_os,
            target_arch: original.target_arch,
            files: request_files,
        };
        let wire = serde_json::to_vec(&request).map_err(|_| GoObservationError::WireEncoding)?;
        if wire.len() > MAX_WIRE {
            return Err(GoObservationError::ResourceLimit);
        }
        let context_bytes =
            serde_json::to_vec(&context).map_err(|_| GoObservationError::WireEncoding)?;
        let directory = files
            .keys()
            .next()
            .ok_or(GoObservationError::InvalidResponse)?
            .rsplit_once('/')
            .map_or("", |(directory, _)| directory);
        let original = ExactClosedPackage {
            directory,
            ..original
        };
        seal_go_request(
            original,
            pin,
            files,
            context,
            (wire, context_bytes),
            "fortress-go-linked-callable-body-v1",
        )
    }
}

fn link_observed_callable(
    original: ExactClosedPackage<'_>,
    receipt: &GoNativeModuleObservation,
    function: &str,
    location: &Span,
    linked: LinkedBody,
) -> Result<NativeCallableOutcome, GoObservationError> {
    let source = original
        .source
        .bytes(&location.path)
        .ok_or(GoObservationError::InvalidResponse)?;
    let origin_ref = canonical_fact_id(
        "go_callable_module_link:v1",
        &(&receipt.binding_sha256, &receipt.response_sha256),
    );
    let link = VerifiedCallableLink {
        language: NativeBodyLanguage::Go,
        namespace: original.package_path,
        function,
        source_path: &location.path,
        source_ref: &super::sha256(source),
        origin_ref: &origin_ref,
        exchange_ref: &linked.exchange,
    };
    Ok(link.attach(linked.evaluation, linked.body))
}

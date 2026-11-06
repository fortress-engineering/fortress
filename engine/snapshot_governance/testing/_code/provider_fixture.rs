//! Owned native Python suite, original source names and an actual assertion oracle.
use fortress_core::declaration::DeclarationBinding;
use fortress_core::evidence_ingest::*;
use fortress_core::provider::*;
use fortress_core::runtime_storage::{RunWorkspace, StoragePolicy};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(1);
const RUNNER: &str = r"import sys,unittest,xml.etree.ElementTree as E
sys.path[:0]=['src','tests']
class Result(unittest.TestResult):
    def __init__(self):
        super().__init__(); self.rows={}
    def startTest(self,test):
        super().startTest(test); self.rows[test.id()]='PASSED'
    def addFailure(self,test,error):
        super().addFailure(test,error); self.rows[test.id()]='FAILED'
    def addError(self,test,error):
        super().addError(test,error); self.rows[test.id()]='ERROR'
    def addSkip(self,test,reason):
        super().addSkip(test,reason); self.rows[test.id()]='SKIPPED'
suite=unittest.defaultTestLoader.loadTestsFromName('test_math.MathTests')
result=Result(); suite.run(result)
root=E.Element('testsuite',name='unit',package='native-project',tests=str(result.testsRun))
for name,status in sorted(result.rows.items()):
    case=E.SubElement(root,'testcase',name=name)
    if status!='PASSED': E.SubElement(case,{'FAILED':'failure','ERROR':'error','SKIPPED':'skipped'}[status])
sys.stdout.write(E.tostring(root,encoding='unicode'))
sys.exit(0 if result.wasSuccessful() else 1)
";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn contract_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::from_value::<fortress_core::contract_coherency::ModuleContract>(value.clone())
        .unwrap()
        .to_canonical_json()
        .unwrap()
        .into_bytes()
}

pub(super) struct NativeFixture {
    pub(super) directory: PathBuf,
    pub(super) root: PathBuf,
}
impl NativeFixture {
    pub(super) fn new() -> Self {
        let mut directory = None;
        for _ in 0..128 {
            let candidate = std::env::temp_dir().join(format!(
                "fortress-native-provider-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    directory = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("owned native fixture: {e}"),
            }
        }
        let directory = directory.expect("bounded unique fixture claim");
        let root = directory.join("subject");
        fs::create_dir(&root).unwrap();
        fs::create_dir(directory.join("storage")).unwrap();
        let fixture = Self { directory, root };
        let mut frame = json!({"$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,"id":"PF-NATIVE",
            "display_name":"Native verification fixture","provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[]});
        let mut owner = frame.clone();
        owner["$schema"] = json!("urn:fortress:schema:v4:module-contract");
        owner["schema_version"] = json!(4);
        owner["id"] = json!("AF-NATIVE-0001");
        owner["provides"] =
            json!([{"id":"CAP-NATIVE-MATH","version":"1.0.0","visibility":"project"}]);
        owner["features"] = json!([{"id":"AF-NATIVE-MATH","version":"1.0.0","requirements":[{"id":"AF-NATIVE-0001-R01",
            "statement":"Addition returns the independently specified sum of two integers.","tests":[],"external_verification":"SUCCESSFUL_EXECUTION"}]}]);
        let mut testing = frame.clone();
        testing["id"] = json!("AF-NATIVE-TESTING-0001");
        testing["relationships"] =
            json!([{"type":"verifies","target":"AF-NATIVE-0001","subjects":["AF-NATIVE-MATH"]}]);
        frame["ecosystem"] = json!({"repository_grammar":1,"standard":{"id":"STD-FORTRESS-ENGINEERING","edition":"1.0.0-draft.2"}});
        fixture.write("contract.json", &contract_bytes(&frame));
        fixture.write(
            "_data/logical_modules/native/contract.json",
            &contract_bytes(&owner),
        );
        fixture.write(
            "_data/logical_modules/native_testing/contract.json",
            &contract_bytes(&testing),
        );
        fixture.write("__fortress/.fsconfig",&serde_json::to_vec_pretty(&json!({"$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,
            "observation_exclusions":[".git"],"logical_modules":[
                {"module":"AF-NATIVE-0001","contract":"_data/logical_modules/native/contract.json","parent":"PF-NATIVE","bindings":[{"kind":"file","path":"src/math_ops.py"}]},
                {"module":"AF-NATIVE-TESTING-0001","contract":"_data/logical_modules/native_testing/contract.json","parent":"AF-NATIVE-0001","bindings":[{"kind":"file","path":"tests/test_math.py"}]}]})).unwrap());
        fixture.write("src/math_ops.py", b"def add(a, b):\n    return a + b\n");
        fixture.write("tests/test_math.py",b"import unittest\nfrom math_ops import add\nclass MathTests(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n");
        let bindings =
            fortress_core::provider_inputs::VerificationBindings::compose(
                vec![Self::requirement()],
            )
            .unwrap();
        fixture.write(
            "__fortress/governance/verification_bindings.json",
            &serde_json::to_vec_pretty(&bindings).unwrap(),
        );
        fixture
    }
    pub(super) fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    pub(super) fn binding(&self) -> DeclarationBinding {
        let view = fortress_core::audit::compile_repository_state_view(&self.root).unwrap();
        view.application
            .unwrap_or_else(|| {
                panic!(
                    "native authority unavailable: {:?}: {:?}",
                    view.status, view.detail
                )
            })
            .declaration
            .binding
    }
    pub(super) fn key() -> InventoryKey {
        InventoryKey {
            namespace: InventoryNamespace::NativeQualified,
            package: Some("native-project".into()),
            target: Some("unit".into()),
            qualified_name: "test_math.MathTests.test_add".into(),
        }
    }
    pub(super) fn requirement() -> ProviderRequirementBinding {
        let key = Self::key();
        ProviderRequirementBinding {
            requirement_id: "AF-NATIVE-0001-R01".into(),
            provider: "native-unittest".into(),
            invocation_scope: "unit".into(),
            selectors: vec![NativeTestSelector {
                namespace: key.namespace,
                package: key.package,
                target: key.target,
                qualified_name: key.qualified_name,
            }],
            authenticated_producer_required: false,
        }
    }
    pub(super) fn command(&self) -> RegisteredProviderCommand {
        let executable = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .flat_map(|directory| {
                if cfg!(windows) {
                    vec![directory.join("python.exe")]
                } else {
                    vec![directory.join("python3"), directory.join("python")]
                }
            })
            .find(|path| path.is_file())
            .expect("qualification requires installed Python");
        let mut inputs = ["src/math_ops.py", "tests/test_math.py"]
            .into_iter()
            .map(|path| ExecutionInput {
                name: path.into(),
                digest: digest(&fs::read(self.root.join(path)).unwrap()),
            })
            .collect::<Vec<_>>();
        inputs.sort_by(|a, b| a.name.cmp(&b.name));
        RegisteredProviderCommand::new(
            "native-unittest-fixture",
            &executable,
            ExecutionDescriptor {
                binary_digest: Some(digest(&fs::read(&executable).unwrap())),
                tool_digest: Some(digest(RUNNER.as_bytes())),
                arguments: Some(vec!["-B".into(), "-c".into(), RUNNER.into()]),
                working_directory: Some(ExecutionDirectory::SubjectRoot),
                inputs,
                environment_dependencies: vec![],
                dependencies_complete: false,
            },
        )
        .unwrap()
    }
    pub(super) fn policy() -> StoragePolicy {
        StoragePolicy {
            reserve_bytes: 0,
            retain_shared_compiler: false,
            ..StoragePolicy::default()
        }
    }
    pub(super) fn retain(
        &self,
        envelope: &EvidenceEnvelope,
        payload: &[u8],
    ) -> fortress_core::provider_inputs::EvidenceInputSet {
        let id = envelope.digest().unwrap();
        let path = format!(
            "__fortress/evidence/imports/{}",
            id.strip_prefix("sha256:").unwrap()
        );
        self.write(
            &format!("{path}/envelope.json"),
            &envelope.to_canonical_bytes().unwrap(),
        );
        self.write(&format!("{path}/payload.bin"), payload);
        fortress_core::provider_inputs::EvidenceInputSet::compose(
            envelope.run_manifest.as_ref().unwrap().binding.clone(),
            vec![fortress_core::provider_inputs::ProviderInputIdentity {
                envelope_digest: id,
                payload_digest: envelope.payload_digest.clone(),
                inventory_digest: Some(envelope.inventory_digest().unwrap()),
            }],
        )
        .unwrap()
    }
}
impl Drop for NativeFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).expect("owned native fixture cleanup");
    }
}

pub(super) struct NativeRunner {
    pub(super) binding: DeclarationBinding,
    pub(super) key: InventoryKey,
    pub(super) calls: usize,
    pub(super) leave_child_record: bool,
    pub(super) last_reaped_pid: Option<u32>,
}
impl TrustedProviderExecutor for NativeRunner {
    fn execute(
        &mut self,
        root: &Path,
        command: &RegisteredProviderCommand,
        workspace: &mut RunWorkspace,
    ) -> Result<ProviderExecutionOutput, ProviderError> {
        self.calls += 1;
        let stdout = workspace.staging().join("native-stdout.xml");
        let stderr = workspace.staging().join("native-stderr.txt");
        let mut child = Command::new(command.binary())
            .args(command.arguments())
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(File::create_new(&stdout)?)
            .stderr(File::create_new(&stderr)?)
            .spawn()?;
        let pid = child.id();
        if let Err(e) = workspace.record_child(pid) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.into());
        }
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(20)
                || fs::metadata(&stdout)?.len() > 1024 * 1024
                || fs::metadata(&stderr)?.len() > 1024 * 1024
            {
                child.kill()?;
                child.wait()?;
                workspace.clear_child(pid)?;
                return Err(ProviderError::ResourceLimit(
                    "native fixture timeout/output",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        child.wait()?;
        self.last_reaped_pid = Some(pid);
        if !self.leave_child_record {
            workspace.clear_child(pid)?;
        }
        if fs::metadata(&stdout)?.len() > 1024 * 1024 || fs::metadata(&stderr)?.len() > 1024 * 1024
        {
            return Err(ProviderError::ResourceLimit("native fixture final output"));
        }
        let payload = fs::read(stdout)?;
        let invocation = InvocationOutcome {
            succeeded: Some(status.success()),
            exit_code: status.code(),
        };
        let manifest = ProviderRunManifest {
            binding: self.binding.clone(),
            provider: "native-unittest".into(),
            provider_version: "fixture-runner-1".into(),
            invocation_scope: "unit".into(),
            execution: command.descriptor().clone(),
            inventory: vec![InventoryMember {
                key: self.key.clone(),
                enabled: true,
            }],
            inventory_complete: true,
            filters: vec![],
            filtering_known: true,
            attempts_complete: true,
            attempts: vec![AttemptCount {
                key: self.key.clone(),
                count: 1,
            }],
            invocation,
            payload_digest: digest(&payload),
            assumptions: vec![],
        };
        Ok(ProviderExecutionOutput {
            payload,
            manifest,
            process_succeeded: status.success(),
            exit_code: status.code(),
        })
    }
}

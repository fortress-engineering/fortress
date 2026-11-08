"""Independent public-protocol countermodels, conformance vectors and attacks."""
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("portable_consumer", Path(__file__).with_name("verify_bundle.py"))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
ROOT = Path(__file__).resolve().parents[2]
D = "sha256:" + "a" * 64


def cell(truth="NO_SUPPORTED_VIOLATION", predicate="CONFORMANCE", authenticated=False):
    binding = dict(subject_ref=D, context_ref=D, authority_ref=D)
    claim = dict(id="claim", scope_ref="scope", kind="SEMANTIC_POLICY", truth=truth,
                 proof_refs=["premise"], semantic_claim=None)
    leaf = dict(id="leaf", source_ref="premise", binding=binding, scope_ref="scope", evidence_class="STATIC_PROOF",
                proposition=truth if truth in ["NO_SUPPORTED_VIOLATION", "SUPPORTED_VIOLATION"] else "OBSERVATION_ONLY",
                payload_digest=D, assumptions=[], valid_until=None)
    proof = dict(schema_version=1, root_node_id="root", nodes=[dict(node_id="root", operator="LEAF", required_refs=["leaf"], children=[])])
    obligation = dict(id="obligation", scope_ref="scope", predicate=predicate, evidence_class="STATIC_PROOF", authenticated_producer_required=authenticated, proof=proof)
    expected = dict(binding=binding, obligations=[obligation], artifacts=[], dimensions={}, profile_digest=D)
    policy = dict(verified_payloads={"leaf": D}, verified_metadata={"leaf": consumer.hashed(leaf)},
                  authenticated_evidence=[], accepted_assumptions=[], assessment_time=None)
    declaration = dict(binding=binding, claims=[claim], proof_manifest=[], required_dimension_manifest={})
    return obligation, declaration, expected, [leaf], policy


class PortableControls(unittest.TestCase):
    def test_native_authority_summary_and_required_edges_are_consistent(self):
        def fixture(omit_edge=False):
            def node(kind, subject, category, inputs, payload):
                body=dict(kind=kind,subject=subject,result="PASS",inputs=sorted(inputs),producer="fixture",producer_semantic_version="1.0.0",evidence_class=category,payload=consumer.legacy_json(payload))
                identity=consumer.sha(json.dumps(body,ensure_ascii=False,separators=(",", ":")).encode())
                return dict(id=identity,**body)
            standard=dict(id="fixture",edition="v1");profile=dict(id="full",version=1)
            source=node("certification_source_snapshot","project","OBSERVATION",[],dict(certification_source_digest=D))
            standard_node=node("standard","fixture","AUTHORITY",[source['id']],dict(edition="v1"))
            definition={"$schema":"urn:fortress:schema:v1:certification-profile","schema_version":1,"id":"full",**{key:True for key in "require_all_applicable_rules require_all_requirement_tests require_behavioral_realization require_generated_verification require_current_artifacts".split()}}
            profile_node=node("certification_profile","full","AUTHORITY",[standard_node['id']],definition)
            leaf=node("rule_check","rule","STATIC_PROOF",[],{})
            obligation=dict(kind="STANDARD_RULE",subject="rule",required_evidence_classes=["STATIC_PROOF"],evidence_refs=[leaf['id']],status="PASS",reason="fixture")
            wrapper=node("certification_obligation:standardrule","rule","AGGREGATE",[profile_node['id']] if omit_edge else [leaf['id'],profile_node['id']],obligation)
            root=node("certification_root","project","AGGREGATE",[wrapper['id']],dict(certification_source_digest=D,standard=standard,profile="full",trusted_assertion_dependencies=[]))
            nodes=sorted([leaf,wrapper,root,source,standard_node,profile_node],key=lambda n:n['id'])
            coverage={key:sum(n['evidence_class'].lower()==key for n in nodes) for key in ['authority','observation','static_proof','executed_test','executed_scenario','trusted_assertion','defeater','aggregate']}
            graph={"$schema":"urn:fortress:schema:v2:evidence-graph","schema_version":2,"subject":D,"standard":standard,"profile":profile,"nodes":nodes,"root_obligations":sorted([root['id'],wrapper['id']]),"coverage":coverage,"provenance":[]}
            certificate={"$schema":"urn:fortress:schema:v1:certification-result","schema_version":1,"profile":profile,"subject":D,"status":"PASS","certification_digest":root['id'],"evidence_graph_digest":consumer.sha(consumer.canonical(graph)),"obligations":[obligation],"summary":dict(obligations=1,**{'pass':1,'fail':0,'stale':0,'missing':0,'invalid':0,'trusted_assertions':0}),"trusted_assertion_dependencies":[]}
            return graph,certificate
        def check(graph,certificate):
            data=consumer.canonical(graph);certificate['evidence_graph_digest']=consumer.sha(data)
            return consumer.graph_check(graph,certificate,data,dict(subject_ref=D,context_ref=D,authority_ref=D))
        graph,certificate=fixture();self.assertEqual(len(check(graph,certificate)),6)
        for change in [lambda g,c:g.update(standard=dict(id="altered",edition="v1")),lambda g,c:c['summary'].update(obligations=0),lambda g,c:c.update(trusted_assertion_dependencies=["omitted"])]:
            graph,certificate=fixture();change(graph,certificate)
            with self.assertRaises(consumer.Invalid):check(graph,certificate)
        graph,certificate=fixture(True)
        with self.assertRaises(consumer.Invalid):check(graph,certificate)

    def test_public_provider_vectors_match_independent_raw_replay(self):
        vectors=json.loads((ROOT/'engine/certification/testing/_data/provider_vectors_v1.json').read_text(encoding='utf-8'))
        checked=0
        for vector in vectors['vectors']:
            if vector.get('accepted') and vector.get('expected'):
                consumer._provider_reference_verify(vector['expected'],vector['raw_utf8'].encode())
                checked+=1
        self.assertGreater(checked,0)

    def test_independent_verifier_matches_assessment_truth_table(self):
        table = {"NO_SUPPORTED_VIOLATION": "SATISFIED", "SUPPORTED_VIOLATION": "NOT_SATISFIED",
                 "NOT_EVALUABLE": "NOT_EVALUABLE", "NOT_APPLICABLE": "NOT_EVALUABLE", "AUTHORIZATION": "NOT_EVALUABLE"}
        for truth, expected in table.items():
            args = cell(truth)
            self.assertEqual(consumer.assess_obligation(*args)["decision"], expected)
        args = cell("SUPPORTED_VIOLATION", "EVALUABILITY")
        self.assertEqual(consumer.assess_obligation(*args)["decision"], "SATISFIED")
        for predicate in ["CONFORMANCE", "EVALUABILITY"]:
            args = cell("AUTHORIZATION", predicate)
            self.assertEqual(consumer.assess_obligation(*args)["decision"], "NOT_EVALUABLE")

    def test_all_any_shared_mandatory_dependencies_exhaustive(self):
        for operator, a, b, mandatory in itertools.product(["ALL", "ANY"], ["T", "F", "U"], ["T", "F", "U"], ["T", "F", "U"]):
            proof = dict(schema_version=1, root_node_id="r", nodes=[dict(node_id="a", operator="LEAF", required_refs=["a"], children=[]),
                dict(node_id="b", operator="LEAF", required_refs=["b"], children=[]), dict(node_id="r", operator=operator, required_refs=["m"], children=["a", "b"])])
            nodes, order = consumer.proof_check(proof, {"a", "b", "m"})
            alternative = ("T" if "T" in [a, b] else "U" if "U" in [a, b] else "F") if operator == "ANY" else ("F" if "F" in [a, b] else "U" if "U" in [a, b] else "T")
            expected = "F" if "F" in [alternative, mandatory] else "U" if "U" in [alternative, mandatory] else "T"
            self.assertEqual(consumer.proof_value(proof, nodes, order, dict(a=a, b=b, m=mandatory)), expected)

    def test_missing_required_leaf_rejects_approval(self):
        args = list(cell())
        args[3] = []
        self.assertEqual(consumer.assess_obligation(*args)["decision"], "INVALID")
        args = list(cell())
        args[4]["verified_payloads"] = {}
        self.assertEqual(consumer.assess_obligation(*args)["decision"], "NOT_EVALUABLE")

    def test_wrong_context_metadata_authentication_assumptions_and_time_fail(self):
        modifications = [lambda a: a[3][0]["binding"].update(context_ref="sha256:" + "b" * 64),
                         lambda a: a[4]["verified_metadata"].clear(), lambda a: a[0].update(authenticated_producer_required=True),
                         lambda a: a[3][0].update(assumptions=["unaccepted"]), lambda a: a[3][0].update(valid_until=1)]
        for modify in modifications:
            args = copy.deepcopy(list(cell()))
            modify(args)
            self.assertEqual(consumer.assess_obligation(*args)["decision"], "NOT_EVALUABLE")

    def test_execution_failure_is_not_a_module_policy_violation(self):
        args = list(cell(predicate="SUCCESSFUL_EXECUTION"))
        args[3][0]["proposition"] = "EXECUTION_FAILED"
        args[4]["verified_metadata"]["leaf"] = consumer.hashed(args[3][0])
        result = consumer.assess_obligation(*args)
        self.assertEqual(result["decision"], "NOT_SATISFIED")
        self.assertEqual(result["blockers"], ["EXECUTION_FAILED"])

    def test_large_integer_and_unicode_vectors_match_jcs(self):
        vectors = json.loads((ROOT / "engine/certification/testing/_data/portable_vectors_v1.json").read_text(encoding="utf-8"))
        for vector in vectors["canonicalization"]:
            self.assertEqual(consumer.canonical(vector["value"]).decode(), vector["canonical"])
        for source in vectors["reject_json"]:
            with self.assertRaises(consumer.Invalid):
                consumer.parse(source.encode())
        for source, expected in [("0.01", "0.01"), ("1e-6", "0.000001"), ("1e-7", "1e-7"), ("-0.0", "0")]:
            self.assertEqual(consumer.canonical(consumer.parse(source.encode())).decode(), expected)

    def test_rfc8785_appendix_b_binary64_vectors(self):
        # Numeric facts from RFC 8785 Appendix B, not a producer-generated oracle.
        vectors = {"0000000000000000":"0", "8000000000000000":"0", "0000000000000001":"5e-324", "8000000000000001":"-5e-324",
            "7fefffffffffffff":"1.7976931348623157e+308", "ffefffffffffffff":"-1.7976931348623157e+308", "4340000000000000":"9007199254740992",
            "4430000000000000":"295147905179352830000", "44b52d02c7e14af5":"9.999999999999997e+22", "44b52d02c7e14af6":"1e+23",
            "44b52d02c7e14af7":"1.0000000000000001e+23", "444b1ae4d6e2ef4e":"999999999999999700000", "444b1ae4d6e2ef4f":"999999999999999900000",
            "444b1ae4d6e2ef50":"1e+21", "3eb0c6f7a0b5ed8c":"9.999999999999997e-7", "3eb0c6f7a0b5ed8d":"0.000001",
            "41b3de4355555553":"333333333.3333332", "41b3de4355555554":"333333333.33333325", "41b3de4355555555":"333333333.3333333",
            "41b3de4355555556":"333333333.3333334", "41b3de4355555557":"333333333.33333343", "becbf647612f3696":"-0.0000033333333333333333",
            "43143ff3c1cb0959":"1424953923781206.2"}
        for bits, expected in vectors.items():
            self.assertEqual(consumer.number(struct.unpack(">d", bytes.fromhex(bits))[0]), expected)

    def test_archive_traversal_bomb_and_duplicate_entries_fail(self):
        with tempfile.TemporaryDirectory(prefix="fortress-portable-controls-") as directory:
            path = Path(directory) / "attack.zip"
            for name in ["../escape.json", "/absolute.json", "C:/absolute.json", "artifacts/../manifest.json", "artifacts\\escape.json"]:
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(name, "{}")
                with self.assertRaises(consumer.Invalid):
                    consumer.Reader(path)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("manifest.json", "{}")
                    archive.writestr("manifest.json", "{}")
            with self.assertRaises(consumer.Invalid):
                consumer.Reader(path)
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", "0" * (consumer.MAX_FILE + 1))
            with self.assertRaises(consumer.Invalid):
                consumer.Reader(path)

    def test_cycles_unknown_references_and_empty_any_never_prove(self):
        for version in [True, 1.0, "1", None, 99]:
            proof = dict(schema_version=version, root_node_id="r", nodes=[dict(node_id="r", operator="LEAF", required_refs=["leaf"], children=[])])
            with self.assertRaises(consumer.Invalid):
                consumer.proof_check(proof, {"leaf"})
        proof = dict(schema_version=1, root_node_id="r", nodes=[dict(node_id="r", operator="ANY", required_refs=[], children=[])])
        with self.assertRaises(consumer.Invalid):
            consumer.proof_check(proof, set())
        with self.assertRaises(consumer.Invalid):
            consumer.topological({"a":["b"], "b":["a"]})
        with self.assertRaises(consumer.Invalid):
            consumer.topological({"a":["missing"]})


def bundle_attacks(path, predicate):
    """Alter a real producer bundle; never rewrite the original or run its code."""
    reader=consumer.Reader(path)
    try:
        original={name:reader.read(name) for name in sorted(reader.names)}
    finally:
        reader.close()
    baseline=consumer.verify(path,predicate)
    consumer.require(baseline['integrity']=='VERIFIED','INVALID_CONTROL','attack control must begin complete')
    count=0
    def run_attack(change):
        nonlocal count
        files=dict(original)
        manifest=consumer.parse(files['manifest.json'])
        statement=consumer.parse(files['statement.json'])
        change(files,manifest,statement)
        files['manifest.json']=consumer.canonical(manifest)
        statement['predicate']['manifest_digest']=consumer.sha(files['manifest.json'])
        files['statement.json']=consumer.canonical(statement)
        with tempfile.TemporaryDirectory(prefix='fortress-portable-attack-') as directory:
            root=Path(directory)/'bundle';root.mkdir()
            for name,data in files.items():
                # Attack metadata may contain an unsafe reference. Only original
                # admitted member names are written by the controlled harness.
                consumer.checked_member(name)
                member=root/name;member.parent.mkdir(exist_ok=True);member.write_bytes(data)
            try:
                result=consumer.verify(root,predicate)
            except (consumer.Invalid,KeyError,TypeError,ValueError):
                pass
            else:
                consumer.require(result['integrity']!='VERIFIED','FAVORABLE_TAMPER','altered required record was admitted')
        count+=1
    run_attack(lambda f,m,s:f.pop(m['artifacts'][0]['member']))
    run_attack(lambda f,m,s:f.update({m['artifacts'][0]['member']:f[m['artifacts'][0]['member']]+b' '}))
    run_attack(lambda f,m,s:m.update(schema_version=99))
    run_attack(lambda f,m,s:m['artifacts'].append(copy.deepcopy(m['artifacts'][0])))
    run_attack(lambda f,m,s:m['artifacts'][0].update(member='../outside-secret'))
    run_attack(lambda f,m,s:m.update(profile_digest='sha256:'+'b'*64))
    run_attack(lambda f,m,s:m['binding'].update(context_ref='sha256:'+'b'*64))
    run_attack(lambda f,m,s:s['predicate'].update(authenticity='AUTHENTICATED'))
    run_attack(lambda f,m,s:s.update(predicateType=predicate.removesuffix('/v1')+'/v2'))
    run_attack(lambda f,m,s:m.update(unrecognized_authority='APPROVED'))
    run_attack(lambda f,m,s:m.update(required_nodes=[]))
    run_attack(lambda f,m,s:m.update(required_payloads={}))
    def altered_standard(files, manifest, statement):
        def artifact(role):
            return next(a for a in manifest['artifacts'] if a['id']==role)
        def replace(role, value):
            row=artifact(role);files.pop(row['member'])
            data=consumer.canonical(value);identity=consumer.sha(data)
            row.update(member='artifacts/'+identity[7:]+'.json',wire_digest=identity,jcs_digest=identity,byte_count=len(data))
            files[row['member']]=data
        graph=consumer.parse(files[artifact('evidence-graph')['member']])
        graph['standard']['edition']='unsupported-altered-authority'
        replace('evidence-graph',graph)
        if any(a['id']=='state-view' for a in manifest['artifacts']):
            state=consumer.parse(files[artifact('state-view')['member']]);state['portable_evidence_graph']=graph
            replace('state-view',state)
    run_attack(altered_standard)
    print(json.dumps({'checked':count,'status':'PASS','original_manifest_digest':baseline['manifest_digest'],'authenticity':'UNVERIFIED'}))


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--rust-vectors":
        vectors = consumer.parse(sys.stdin.buffer.read(consumer.MAX_FILE + 1))
        for vector in vectors:
            result = consumer.replay_check(vector["declaration"], vector["assessment"], vector["replay"])
            consumer.require(result == vector["expected"], "INCONSISTENT_RESULT", "independent expected outcome differs")
        print(json.dumps({"checked": len(vectors), "status": "PASS", "authenticity": "UNVERIFIED"}))
    elif len(sys.argv)==4 and sys.argv[1]=='--bundle-attacks':
        bundle_attacks(sys.argv[2],sys.argv[3])
    else:
        unittest.main()

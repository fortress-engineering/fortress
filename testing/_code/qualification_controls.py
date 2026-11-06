"""Independent harness countermodels; no frozen held-out case is scored here."""
import copy
import hashlib
import unittest
from semantic_qualification import observed_endpoint, score

SITE="rust_operation_site:v1:sha256:"+"a"*64
MUTATIONS=dict(relations=[],directed_relations=0,extra_independent_samples=0)


def fixture(expected="SUPPORTED_VIOLATION",production=True):
    source='pub fn entry() { let _ = std::fs::write("control", b"x"); }\n'
    case=dict(case_id="independent-harness-countermodel",source=source,source_sha256=hashlib.sha256(source.encode()).hexdigest(),
        effect="filesystem.write",disposition="DENY",stratum="HARNESS_COUNTERMODEL",ground_truth="LITERAL_PRIMITIVE_SEMANTICS",
        expected_reporting=[expected],expected_blocking=expected=="SUPPORTED_VIOLATION" and production,
        required_supported_control=True,holdout="NOT_A_HELDOUT_CASE",provenance="PRODUCTION" if production else "TEST_ONLY")
    evaluation=dict(authorization=None,verdict="SUPPORTED_VIOLATION",blocking_eligibility="BLOCK_SUPPORTED" if production else "ADVISORY_ONLY",
        proof_refs=[SITE],proof_graph={"schema_version":1,"root_node_id":"root","nodes":[dict(node_id="root",operator="LEAF",required_refs=[SITE],children=[])]})
    row=dict(case_id=case["case_id"],status="OBSERVED",equal_differentials=True,equal_metadata_control=True,
        module=dict(conclusions=[evaluation],observations=[dict(effect="filesystem.write",path="sample/_code/lib.rs",
            line=1,column=25,operation="std::fs::write",operation_site_id=SITE)]),
        operation_inventory=[dict(semantic_operation_site_id=SITE,reference="std::fs::write",
            provenance=dict(path="sample/_code/lib.rs",location=dict(line=1,column=25)))])
    return case,row


def matched(case,row):
    return score([case],[row],MUTATIONS)["scored"][0]["match"]


class QualificationHarnessControls(unittest.TestCase):
    """Challenge the scorer, not production code or corpus accuracy."""

    def test_literal_positive_requires_real_site_and_proof_links(self):
        case,row=fixture()
        self.assertTrue(matched(case,row))
        for field in ["operation_inventory"]:
            bad=copy.deepcopy(row);bad[field]=[];self.assertFalse(matched(case,bad))
        bad=copy.deepcopy(row);bad["module"]["observations"]=[];self.assertFalse(matched(case,bad))
        for field,value in [("proof_refs",[]),("proof_graph",None)]:
            bad=copy.deepcopy(row);bad["module"]["conclusions"][0][field]=value
            self.assertFalse(matched(case,bad))

    def test_favorable_absence_cannot_validate_known_positive(self):
        case,row=fixture()
        row["module"]["conclusions"][0].update(verdict="NO_SUPPORTED_VIOLATION",blocking_eligibility="ADVISORY_ONLY")
        self.assertFalse(matched(case,row))

    def test_always_violation_cannot_validate_literal_negative_or_unknown(self):
        for expected in ["NO_SUPPORTED_VIOLATION","NOT_EVALUABLE","NOT_APPLICABLE"]:
            case,row=fixture(expected)
            self.assertFalse(matched(case,row))

    def test_omitted_cases_remain_in_required_denominator(self):
        case,_=fixture()
        result=score([case],[],MUTATIONS)
        self.assertEqual(len(result["scored"]),1)
        self.assertTrue(result["scored"][0]["required"])
        self.assertFalse(result["scored"][0]["match"])
        self.assertEqual(result["scored"][0]["status"],"INCOMPLETE")

    def test_test_only_positive_does_not_gain_blocking_eligibility(self):
        case,row=fixture(production=False)
        self.assertTrue(matched(case,row))
        row["module"]["conclusions"][0]["blocking_eligibility"]="BLOCK_SUPPORTED"
        self.assertFalse(matched(case,row))

    def test_different_cold_or_metadata_results_never_pass(self):
        for field in ["equal_differentials","equal_metadata_control"]:
            case,row=fixture();row[field]=False;self.assertFalse(matched(case,row))

    def test_driver_failure_is_not_an_invalid_source_or_success(self):
        case,row=fixture("NOT_EVALUABLE")
        row=dict(case_id=case["case_id"],status="DRIVER_PANIC")
        self.assertEqual(observed_endpoint(row),("DRIVER_FAILURE",False))
        self.assertFalse(matched(case,row))

    def test_mutation_relations_cannot_use_omitted_or_duplicate_endpoints(self):
        case,row=fixture()
        with self.assertRaises(ValueError):score([case],[row,row],MUTATIONS)
        with self.assertRaises(ValueError):score([case],[dict(row,case_id="foreign")],MUTATIONS)


if __name__=="__main__":
    unittest.main()

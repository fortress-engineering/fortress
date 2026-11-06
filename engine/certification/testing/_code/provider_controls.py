"""Manual protocol controls; no Fortress conclusions supply expected answers."""
import copy
import unittest
import provider_reference as ref

def fixture(terminal=''):
    raw=f'<testsuite name="unit" package="native"><testcase name="tests.Math.test_add">{terminal}</testcase></testsuite>'.encode()
    binding=dict(subject_ref='sha256:'+'a'*64,context_ref='sha256:'+'b'*64,authority_ref='sha256:'+'c'*64)
    key=dict(namespace='NATIVE_QUALIFIED',package='native',target='unit',qualified_name='tests.Math.test_add')
    invocation=dict(succeeded=True,exit_code=0)
    execution=dict(binary_digest='sha256:'+'d'*64,tool_digest='sha256:'+'e'*64,arguments=['run'],working_directory='SUBJECT_ROOT',
        inputs=[dict(name='source',digest=binding['subject_ref'])],environment_dependencies=[],dependencies_complete=True)
    manifest=dict(binding=binding,provider='native',provider_version='1',invocation_scope='unit',execution=execution,
        inventory=[dict(key=key,enabled=True)],inventory_complete=True,filters=[],filtering_known=True,
        attempts_complete=True,attempts=[dict(key=key,count=1)],invocation=invocation,payload_digest=ref.digest(raw),assumptions=[])
    outcome='FAILED' if terminal in ('<failure/>','<error/>') else 'SKIPPED' if terminal=='<skipped/>' else 'PASSED'
    envelope={'$schema':'urn:fortress:derived:v1:provider-evidence','schema_version':1,'normalizer_semantic_version':'1.0.0','format':'JUNIT_XML',
        'provider':'native','provider_version':'1','media_type':'application/xml','payload_digest':ref.digest(raw),'run_manifest':manifest,
        'observations':[dict(key=key,outcome=outcome,attempts=1,retry_metadata_present=False,finding_count=None)],
        'invocation':invocation,'invocation_basis':'COMPANION_MANIFEST','limitations':[],'authenticity':'UNVERIFIED'}
    requirement=dict(requirement_id='AF-NATIVE-0001-R01',provider='native',invocation_scope='unit',selectors=[key],authenticated_producer_required=False)
    return envelope,raw,binding,requirement

def host(envelope):
    identity=ref.digest(ref.canonical(envelope))
    return dict(admitted_envelopes=[identity],current_executions={identity:copy.deepcopy(envelope['run_manifest']['execution'])},accepted_assumptions=[])

class IndependentProviderControls(unittest.TestCase):
    def test_manual_native_assertion_reporting_and_complete_scope(self):
        e,raw,b,r=fixture()
        self.assertTrue(ref.verify(e,raw)[1])
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'SATISFIED')
    def test_known_failure_is_verification_failure_not_a_module_violation(self):
        for terminal in ('<failure/>','<error/>'):
            e,raw,b,r=fixture(terminal)
            self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_SATISFIED')
    def test_skip_is_incomplete_even_with_successful_invocation(self):
        e,raw,b,r=fixture('<skipped/>')
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_EVALUABLE')
    def test_each_source_context_and_authority_axis_is_required(self):
        e,raw,b,r=fixture()
        for axis in b:
            wrong=dict(b);wrong[axis]='sha256:'+'f'*64
            self.assertEqual(ref.resolve(e,raw,wrong,r,host(e)),'NOT_EVALUABLE')
    def test_unknown_dependencies_refuse_retained_replay(self):
        e,raw,b,r=fixture();e['run_manifest']['execution']['dependencies_complete']=False
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_EVALUABLE')
    def test_changed_current_binary_inputs_argv_tool_or_environment_refuses(self):
        e,raw,b,r=fixture()
        for field,value in [('binary_digest','sha256:'+'f'*64),('tool_digest','sha256:'+'f'*64),('arguments',['changed']),
                            ('inputs',[]),('environment_dependencies',[dict(name='ENV',digest='sha256:'+'f'*64)])]:
            policy=host(e);policy['current_executions'][ref.digest(ref.canonical(e))][field]=value
            self.assertEqual(ref.resolve(e,raw,b,r,policy),'NOT_EVALUABLE')
    def test_unsigned_name_and_candidate_freshness_are_not_authority(self):
        e,raw,b,r=fixture();r['authenticated_producer_required']=True
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_EVALUABLE')
        e['fresh']=True
        with self.assertRaises(ValueError):ref.verify(e,raw)
    def test_raw_bytes_reproduce_exact_rows_and_attempt_number_types(self):
        e,raw,_,_=fixture();e['observations'][0]['attempts']=True
        with self.assertRaises(ValueError):ref.verify(e,raw)
        e,raw,_,_=fixture();e['observations'][0]['outcome']='FAILED'
        with self.assertRaises(ValueError):ref.verify(e,raw)
        with self.assertRaises(ValueError):ref.verify(e,raw+b' ')
    def test_filters_and_unaccepted_assumptions_withhold_support(self):
        for field,value in [('filters',['one-test']),('filtering_known',False),('inventory_complete',False),('assumptions',['external-assumption'])]:
            e,raw,b,r=fixture();e['run_manifest'][field]=value
            self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_EVALUABLE')
    def test_invocation_failure_remains_distinct_from_member_outcome(self):
        e,raw,b,r=fixture();e['run_manifest']['invocation']['succeeded']=False
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_SATISFIED')
    def test_accepted_failure_is_retained_when_complete_run_accounting_is_unknown(self):
        e,raw,b,r=fixture();e['run_manifest']['filters']=['partial']
        e['run_manifest']['invocation']['succeeded']=False
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_SATISFIED')
        e['run_manifest']['inventory_complete']=False
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_EVALUABLE')
    def test_missing_selected_member_is_not_vacuous_success(self):
        e,raw,b,r=fixture();r['selectors'][0]=dict(r['selectors'][0],qualified_name='missing')
        self.assertEqual(ref.resolve(e,raw,b,r,host(e)),'NOT_EVALUABLE')

if __name__=='__main__':unittest.main()

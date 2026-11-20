"""Non-numerical integrity and lifecycle controls for large projections."""
import sys
sys.dont_write_bytecode=True
import copy,hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'engine/snapshot_governance/_code'))
import bounded_io as b
import quality_certificate as q
sys.path.insert(0,str(ROOT/'testing/_code'))
import performance_runner as runner
import performance_qualification as qualification
class Controls(unittest.TestCase):
 def test_byte_exact_all_boundary_lengths(self):
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory)/"input"
   for length in [0,1,65535,65536,65537,3*65536+7]:
    raw=(b"boundary"*((length+7)//8))[:length];p.write_bytes(raw)
    self.assertEqual(b.hash_ordinary(p),(length,"sha256:"+hashlib.sha256(raw).hexdigest()))
    self.assertEqual(b.read_ordinary(p),raw)
    if length:self.assertRaises(OSError,b.hash_ordinary,p,length-1)
 def test_streaming_never_requests_unbounded_input(self):
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory)/"input";p.write_bytes(b"x"*(2*1024**2+17));seen=[];original=b.os.fdopen
   class Stream:
    def __init__(self,stream):self.stream=stream
    def __enter__(self):return self
    def __exit__(self,*args):return self.stream.__exit__(*args)
    def fileno(self):return self.stream.fileno()
    def read(self,maximum=-1):
     seen.append(maximum);assert 0<maximum<=65536;return self.stream.read(maximum)
   with patch.object(b.os,"fdopen",lambda *args:Stream(original(*args))):
    self.assertEqual(b.hash_ordinary(p)[0],p.stat().st_size)
   self.assertGreater(len(seen),32)
 def test_source_drift_never_returns_a_favorable_digest(self):
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory)/"input";p.write_bytes(b"x"*65537);old=p.stat();factory=hashlib.sha256
   class Hasher:
    def __init__(self):self.h=factory();self.changed=False
    def update(self,raw):
     self.h.update(raw)
     if not self.changed:
      self.changed=True;p.write_bytes(b"y"*65537);os.utime(p,ns=(old.st_atime_ns,old.st_mtime_ns+10000000))
    def hexdigest(self):return self.h.hexdigest()
   with patch.object(b.hashlib,"sha256",Hasher):self.assertRaises(OSError,b.hash_ordinary,p)
 def test_missing_and_directory_inputs_are_not_evidence(self):
  with tempfile.TemporaryDirectory() as directory:
   self.assertRaises(OSError,b.hash_ordinary,Path(directory)/"missing")
   self.assertRaises(OSError,b.hash_ordinary,Path(directory))
 def test_verified_stream_copy_preserves_exact_bytes(self):
  with tempfile.TemporaryDirectory() as directory:
   source=Path(directory)/"source";target=Path(directory)/"target"
   raw=b"exact retained projection"*10000;source.write_bytes(raw)
   size,digest=b.hash_ordinary(source)
   q.atomic_write(target,q.FileMaterialization(source,size,digest))
   self.assertEqual(target.read_bytes(),raw)
   self.assertEqual(source.read_bytes(),raw)
   self.assertEqual(list(Path(directory).glob("*.pending")),[])
 def test_wrong_digest_and_changed_preimage_preserve_existing_destination(self):
  with tempfile.TemporaryDirectory() as directory:
   source=Path(directory)/"source";target=Path(directory)/"target"
   source.write_bytes(b"old source");target.write_bytes(b"preserved bytes")
   size,digest=b.hash_ordinary(source)
   for binding in [q.FileMaterialization(source,size,"sha256:"+"0"*64),q.FileMaterialization(source,size+1,digest)]:
    with self.assertRaises((OSError,q.CertificateError)):q.atomic_write(target,binding)
    self.assertEqual(target.read_bytes(),b"preserved bytes")
   source.write_bytes(b"source drift")
   with self.assertRaises((OSError,q.CertificateError)):q.atomic_write(target,q.FileMaterialization(source,size,digest))
   self.assertEqual(target.read_bytes(),b"preserved bytes")
   self.assertEqual(list(Path(directory).glob("*.pending")),[])
 def test_stream_copy_rejects_partial_output(self):
  with tempfile.TemporaryDirectory() as directory:
   source=Path(directory)/"source";source.write_bytes(b"complete bytes")
   class Incomplete:
    def write(self,raw):return len(raw)-1
   with self.assertRaises(OSError):b.copy_ordinary(source,Incomplete())
 def test_malformed_bindings_are_refused_before_destination_creation(self):
  with tempfile.TemporaryDirectory() as directory:
   target=Path(directory)/"not_created"/"target";source=Path(directory)/"source";source.write_bytes(b"source")
   for count,digest in [(True,"sha256:"+"0"*64),(-1,"sha256:"+"0"*64),(512*1024**2+1,"sha256:"+"0"*64),(1,"forged")]:
    with self.assertRaises(q.CertificateError):q.atomic_write(target,q.FileMaterialization(source,count,digest))
    self.assertFalse(target.parent.exists())

 def materialized(self,directory):
  raw=b"canonical projection\n";path=directory/"projection.json";path.write_bytes(raw)
  subject="sha256:"+"a"*64
  record={"$schema":"urn:fortress:diagnostic:v1:projection-materialization","schema_version":1,"claim":"STATIC_PROJECTIONS_ONLY","source_domain":"CERTIFICATION_SOURCE_IDENTITY","source_ref":subject,"execution":"NOT_RUN","certification":"NOT_ISSUED","authenticity":"UNVERIFIED","complete":True,"files":[{"logical_path":"_info/projection.json","file_name":"projection.json","bytes":len(raw),"digest":q.sha256_bytes(raw)}],"phase_measurements":[]}
  return subject,record
 def test_complete_materializations_verify_all_bytes_and_reject_tampering(self):
  with tempfile.TemporaryDirectory() as directory:
   directory=Path(directory);subject,record=self.materialized(directory)
   (directory/"manifest.json").write_text(json.dumps(record),encoding="utf-8")
   self.assertEqual(q.load_projection_materialization(directory,subject,{"_info/projection.json"})["_info/projection.json"],(record["files"][0]["bytes"],record["files"][0]["digest"]))
   (directory/"projection.json").write_bytes(b"tampered")
   with self.assertRaises(q.CertificateError):q.load_projection_materialization(directory,subject,{"_info/projection.json"})
 def test_missing_incomplete_unsupported_and_traversing_manifests_never_verify(self):
  with tempfile.TemporaryDirectory() as directory:
   directory=Path(directory);subject,original=self.materialized(directory)
   variants=[]
   for key,value in [("schema_version",2),("complete",False),("complete",1),("execution","PASS"),("source_ref","sha256:"+"b"*64)]:
    record=copy.deepcopy(original);record[key]=value;variants.append(record)
   record=copy.deepcopy(original);record["files"][0]["file_name"]="../outside.json";variants.append(record)
   record=copy.deepcopy(original);record["files"]=[];variants.append(record)
   for phases in [[{}],[{"phase":"unknown","wall_time_ns":2**53}],[False]]:
    record=copy.deepcopy(original);record["phase_measurements"]=phases;variants.append(record)
   for record in variants:
    with self.subTest(record=record):
     (directory/"manifest.json").write_text(json.dumps(record),encoding="utf-8")
     with self.assertRaises(q.CertificateError):q.load_projection_materialization(directory,subject,{"_info/projection.json"})
 def test_duplicate_materialization_identities_are_explicit_conflicts(self):
  with tempfile.TemporaryDirectory() as directory:
   directory=Path(directory);subject,record=self.materialized(directory);record["files"].append(record["files"][0].copy())
   (directory/"manifest.json").write_text(json.dumps(record),encoding="utf-8")
   with self.assertRaises(q.CertificateError):q.load_projection_materialization(directory,subject,{"_info/projection.json","_info/other.json"})
 def test_timing_statistics_do_not_invent_tails_or_accept_inexact_counts(self):
  ten=runner.distribution(list(range(10)));self.assertNotIn("p99_ns",ten);self.assertNotIn("p95_ns",ten)
  hundred=runner.distribution(list(range(100)));self.assertEqual(hundred["p99_ns"],98);self.assertEqual(hundred["p95_ns"],94)
  for bad in [[],[True],[1.5],[-1],[2**53]]:
   with self.assertRaises(ValueError):runner.distribution(bad)
 def test_workload_limits_population_and_generation_are_deterministic(self):
  raw=(ROOT/"testing/_data/performance_workloads.json").read_bytes();manifest=runner.workload_manifest(raw);row=manifest["workloads"][0]
  with tempfile.TemporaryDirectory() as directory:
   one=Path(directory)/"one";two=Path(directory)/"two";a=runner.generate_fixture(one,row);b=runner.generate_fixture(two,row);self.assertEqual(a,b)
   first={str(p.relative_to(one)):p.read_bytes() for p in one.rglob("*") if p.is_file()};second={str(p.relative_to(two)):p.read_bytes() for p in two.rglob("*") if p.is_file()};self.assertEqual(first,second)
   self.assertFalse((one/"__fortress").exists());self.assertEqual(a["lines_including_cargo_and_module_declarations"],sum(v.count(b"\n") for v in first.values()))
  for key,value in [("numerical_performance_requirements",True),("required_qualification",{}),("generator","arbitrary_code")]:
   invalid=copy.deepcopy(manifest);invalid[key]=value
   with self.assertRaises(ValueError):runner.workload_manifest(json.dumps(invalid).encode())
 def test_source_bound_qualification_integrity_never_authenticates_assertions(self):
  source="sha256:"+"a"*64;report="sha256:"+"b"*64
  observations=[{"id":name,"digest":report,"bytes":1} for name in qualification.POPULATION]
  proof={"source_ref":source,"populations":qualification.POPULATION.copy(),"unfiltered_suite":True,"independent_cold":True,"reports":{name:report for name in qualification.POPULATION}}
  manifest=(ROOT/"testing/_data/performance_workloads.json").read_bytes()
  selection=qualification.digest((ROOT/"engine/snapshot_governance/testing/_data/resident_campaign_v2.json").read_bytes())
  record=qualification.compose(source,report,manifest,observations,["Uncontrolled host; claims and references remain unauthenticated."],proof,selection_manifest_digest=selection)
  self.assertEqual(qualification.check(record,source)["authenticity"],"UNVERIFIED")
  malformed=json.loads(manifest);malformed["schema_version"]=3
  with self.assertRaisesRegex(ValueError,"UNSUPPORTED_VERSION"):qualification.compose(source,report,json.dumps(malformed).encode(),observations,["Unsupported manifest."],proof,selection_manifest_digest=selection)
  changed=copy.deepcopy(record);changed["numeric_performance_certification"]=True
  with self.assertRaises(ValueError):qualification.check(changed,source)
  with self.assertRaises(ValueError):qualification.check(record,"sha256:"+"c"*64)
  for field in ["independent_cold","unfiltered_suite"]:
   changed=copy.deepcopy(proof);changed[field]=False
   with self.assertRaisesRegex(ValueError,"INCOMPLETE_CORRECTNESS_EVIDENCE"):qualification.compose(source,report,manifest,observations,["Incomplete."],changed,selection_manifest_digest=selection)
  for name in ["verified_baseline_restorations","lifecycle_operations"]:
   missing=[observation for observation in observations if observation["id"]!=name]
   with self.assertRaisesRegex(ValueError,"MISSING_INDEPENDENT_REPORT_REFERENCE"):qualification.compose(source,report,manifest,missing,["Missing reports."],proof,selection_manifest_digest=selection)
  with self.assertRaisesRegex(ValueError,"INVALID_SELECTION_IDENTITY"):qualification.compose(source,report,manifest,observations,["Missing selection."],proof)
  historical=json.loads(manifest)
  historical.update({"$schema":"urn:fortress:research:v1:performance-workloads","id":"canonical-performance-workloads-v1","schema_version":1,"required_qualification":qualification.HISTORICAL_POPULATION})
  historical_proof={**proof,"populations":qualification.HISTORICAL_POPULATION,"reports":{name:report for name in qualification.HISTORICAL_POPULATION}}
  historical_observations=[{"id":name,"digest":report,"bytes":1} for name in historical_proof["reports"]]
  legacy=qualification.compose(source,report,json.dumps(historical).encode(),historical_observations,["Historical record."],historical_proof)
  self.assertEqual(legacy["schema_version"],1)
  self.assertEqual(qualification.check(legacy,source)["integrity"],"VALID")
  with self.assertRaisesRegex(ValueError,"INCOMPLETE_CORRECTNESS_EVIDENCE"):qualification.compose(source,report,manifest,historical_observations,["Historical record."],historical_proof,selection_manifest_digest=selection)
 def test_diagnostic_deadline_retains_uncertain_descendant_ownership(self):
  class Leaf:
   pid=1234
   returncode=None
   def communicate(self,timeout):raise subprocess.TimeoutExpired(["owned-probe"],timeout)
   def terminate(self):self.returncode=-15
   def wait(self,timeout=None):return self.returncode
   def poll(self):return self.returncode
  work=Mock();leaf=Leaf()
  with patch.object(q.subprocess,"Popen",return_value=leaf),patch.object(q.time,"monotonic_ns",side_effect=iter(range(0,10**12,10**9))):
   with self.assertRaises(q.CertificateError):q.run_command(ROOT,["owned-probe"],{},workspace=work,timeout_seconds=1)
  work.record_child.assert_called_once_with(1234);work.clear_child.assert_not_called()
  self.assertEqual(leaf.returncode,-15)
 def test_invalid_deadlines_refuse_before_process_creation(self):
  for value in [0,-1,True,1.5,86401]:
   with patch.object(q.subprocess,"Popen") as spawn:
    with self.assertRaises(q.CertificateError):q.run_command(ROOT,["owned-probe"],{},workspace=Mock(),timeout_seconds=value)
    spawn.assert_not_called()

if __name__=="__main__":unittest.main()

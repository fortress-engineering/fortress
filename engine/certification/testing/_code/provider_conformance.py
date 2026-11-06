"""Independent provider protocol gate; no performance or empirical-precision claim."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import unittest
import provider_controls
import provider_reference as reference

ROOT=Path(__file__).resolve().parents[4]
VECTORS=Path(__file__).resolve().parents[1]/'_data/provider_vectors_v1.json'
CAPTURE_LIMIT=4*1024*1024

def file_digest(path:Path)->str:
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(64*1024),b''):digest.update(block)
    return 'sha256:'+digest.hexdigest()

def execute(command:list[str],directory:Path)->int:
    """Own one direct, read-only CLI child, bounded output and a fixed deadline."""
    out=directory/'stdout.txt';err=directory/'stderr.txt'
    with out.open('xb') as stdout,err.open('xb') as stderr:
        process=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
        start=time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic()-start>30 or out.stat().st_size>CAPTURE_LIMIT or err.stat().st_size>CAPTURE_LIMIT:
                    process.kill();process.wait();raise RuntimeError('provider comparison deadline/output limit')
                time.sleep(.01)
            status=process.wait()
        finally:
            if process.poll() is None:process.kill();process.wait()
    if out.stat().st_size>CAPTURE_LIMIT or err.stat().st_size>CAPTURE_LIMIT:raise RuntimeError('provider comparison final output limit')
    return status

def run(executable:Path,workdir:Path)->dict:
    if workdir.resolve().is_relative_to(ROOT):raise ValueError('comparison scratch must remain outside product source')
    workdir.mkdir()
    before=file_digest(executable)
    tests=unittest.defaultTestLoader.loadTestsFromModule(provider_controls)
    controls=unittest.TextTestRunner(verbosity=1).run(tests)
    if not controls.wasSuccessful():raise RuntimeError('independent manual provider controls failed')
    vector_bytes=VECTORS.read_bytes()
    document=reference.unique_json(vector_bytes)
    if document['evidence_scope']!='SYNTHETIC_PROTOCOL_CONTROLS_NOT_ACTUAL_EXECUTION':raise ValueError('incorrect oracle scope')
    identities=set();records=[]
    for index,vector in enumerate(document['vectors']):
        if vector['id'] in identities:raise ValueError('duplicate vector identity')
        identities.add(vector['id'])
        case=workdir/f'case-{index:03}';case.mkdir()
        raw=vector['raw_utf8'].encode('utf-8');payload=case/'payload.bin';payload.write_bytes(raw)
        output=case/'envelope.json'
        command=[str(executable),'evidence',vector['format'],str(payload),'--output',str(output)]
        if vector['manifest'] is not None:
            manifest=case/'manifest.json';manifest.write_bytes(reference.canonical(vector['manifest']))
            command+=['--manifest',str(manifest)]
        # Check independent literal expectations before observing native output.
        if vector['accepted']:reference.verify(vector['expected'],raw)
        status=execute(command,case)
        if vector['accepted']:
            if status!=0:raise AssertionError(f"{vector['id']}: native refusal: {(case/'stderr.txt').read_text(encoding='utf-8')}")
            if not output.is_file() or output.stat().st_size>CAPTURE_LIMIT:raise AssertionError('missing or excessive normalized output')
            content=output.read_bytes();actual=reference.unique_json(content)
            if reference.canonical(actual)!=content:raise AssertionError('noncanonical native provider output')
            if reference.canonical(actual)!=reference.canonical(vector['expected']):raise AssertionError(f"{vector['id']}: native output differs from the frozen literal oracle")
            reference.verify(actual,raw)
        elif status!=2 or output.exists():raise AssertionError(f"{vector['id']}: malformed input was not refused")
        records.append(dict(id=vector['id'],expected_acceptance=vector['accepted'],status='PASS'))
    if file_digest(executable)!=before:raise AssertionError('native executable changed during comparison')
    return dict(status='PASS',scope='CORRECTNESS_PROTOCOL_REPLAY_NOT_PERFORMANCE_OR_POPULATION_VALIDATION',
        executable_digest=before,vector_digest=reference.digest(vector_bytes),manual_controls=controls.testsRun,
        comparisons=records,human_adjudication=False,real_world_precision=None,false_positive_rate=None,confidence_interval=None)

def main()->None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable',required=True,type=Path)
    parser.add_argument('--workdir',required=True,type=Path)
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    report=run(args.executable.resolve(),args.workdir)
    with args.report.open('xb') as stream:stream.write((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    print(json.dumps(dict(status=report['status'],manual_controls=report['manual_controls'],comparisons=len(report['comparisons']),vector_digest=report['vector_digest'])))

if __name__=='__main__':main()

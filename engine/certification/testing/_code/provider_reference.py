"""Independent retained-provider replay and conservative requirement assessment.

No Fortress producer or evaluator is imported. Raw XML/JSON is parsed with the
Python standard library. The caller supplies trusted expected bindings, selected
requirements and current execution descriptors. This consumer cannot receive a
fresh capability through serialized reporting and never authenticates a name.
"""
import hashlib
import json
import re
from provider_xml import unique_json,parse_junit,require,MAX_BYTES,MAX_ROWS
from provider_sarif import parse as parse_sarif

DIGEST=re.compile(r'sha256:[0-9a-f]{64}\Z')
UNKNOWN=dict(succeeded=None,exit_code=None)

def canonical(value):
    def check(value):
        if type(value) is dict:
            require(all(type(k) is str and k.isascii() for k in value),'closed DTO keys')
            for child in value.values():check(child)
        elif type(value) is list:
            for child in value:check(child)
        elif type(value) is int:require(abs(value)<=2**53-1,'exact public integer')
        else:require(value is None or type(value) in (str,bool),'closed DTO value')
    check(value)
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')

def digest(payload):return 'sha256:'+hashlib.sha256(payload).hexdigest()

def shape(value,fields):require(type(value) is dict and set(value)==set(fields.split()),'closed record shape')

def execution(value):
    shape(value,'binary_digest tool_digest arguments working_directory inputs environment_dependencies dependencies_complete')
    for field in ('binary_digest','tool_digest'):
        require(value[field] is None or type(value[field]) is str and DIGEST.fullmatch(value[field]),'execution identity')
    require(value['arguments'] is None or type(value['arguments']) is list and len(value['arguments'])<=MAX_ROWS
        and all(type(a) is str for a in value['arguments']),'argv')
    require(value['working_directory'] in (None,'SUBJECT_ROOT'),'execution directory')
    require(type(value['dependencies_complete']) is bool,'execution closure status')
    if value['dependencies_complete']:
        require(all(value[f] is not None for f in ('binary_digest','tool_digest','arguments','working_directory')),'incomplete descriptor claiming closure')
    for field in ('inputs','environment_dependencies'):
        entries=value[field];require(type(entries) is list and len(entries)<=MAX_ROWS,'execution dependency bound')
        names=[]
        for entry in entries:
            shape(entry,'name digest');require(type(entry['name']) is str and entry['name'],'execution dependency name')
            require(type(entry['digest']) is str and DIGEST.fullmatch(entry['digest']),'execution dependency identity');names.append(entry['name'])
        require(names==sorted(set(names)),'execution dependency ambiguity')

def check_invocation(value):
    shape(value,'succeeded exit_code')
    require(value['succeeded'] is None or type(value['succeeded']) is bool,'process success')
    require(value['exit_code'] is None or type(value['exit_code']) is int and -(2**31)<=value['exit_code']<2**31,'process exit')

def key(value):
    shape(value,'namespace package target qualified_name')
    require(value['namespace'] in ('NATIVE_QUALIFIED','GOVERNED_TEST_ID'),'identity namespace')
    require(type(value['qualified_name']) is str and value['qualified_name'],'qualified name')
    for field in ('package','target'):require(value[field] is None or type(value[field]) is str and value[field],'native qualifier')
    if value['namespace']=='GOVERNED_TEST_ID':
        require(value['package'] is None and value['target'] is None and value['qualified_name'].startswith('T-'),'governed namespace')
    return tuple(value[name] for name in ('namespace','package','target','qualified_name'))

def order(identity):
    ns,package,target,name=identity
    return (0 if ns=='NATIVE_QUALIFIED' else 1,package is not None,package or '',target is not None,target or '',name)

def ordered(values,identity):
    keys=[identity(value) for value in values]
    require(keys==sorted(set(keys),key=order),'duplicate/unordered native records')
    return keys

def verify(envelope,raw):
    shape(envelope,'$schema schema_version normalizer_semantic_version format provider provider_version media_type payload_digest run_manifest observations invocation invocation_basis limitations authenticity')
    require(envelope['$schema']=='urn:fortress:derived:v1:provider-evidence' and type(envelope['schema_version']) is int and envelope['schema_version']==1,'provider edition')
    require(envelope['normalizer_semantic_version']=='1.0.0' and envelope['authenticity']=='UNVERIFIED','normalizer/authenticity')
    require(len(raw)<=MAX_BYTES and envelope['payload_digest']==digest(raw),'raw payload binding')
    require(type(envelope['observations']) is list and len(envelope['observations'])<=MAX_ROWS,'row bound')
    observed=ordered(envelope['observations'],lambda row:key(row['key']))
    check_invocation(envelope['invocation'])
    manifest=envelope['run_manifest']
    inventory=[];attempts={}
    if manifest is not None:
        shape(manifest,'binding provider provider_version invocation_scope execution inventory inventory_complete filters filtering_known attempts_complete attempts invocation payload_digest assumptions')
        for field in ('provider','provider_version','payload_digest'):require(manifest[field]==envelope[field],'manifest metadata binding')
        shape(manifest['binding'],'subject_ref context_ref authority_ref')
        execution(manifest['execution']);check_invocation(manifest['invocation'])
        for field in ('inventory_complete','filtering_known','attempts_complete'):require(type(manifest[field]) is bool,'manifest completeness flag')
        require(type(manifest['filters']) is list and all(type(v) is str for v in manifest['filters']),'manifest filters')
        require(type(manifest['assumptions']) is list and manifest['assumptions']==sorted(set(manifest['assumptions'])),'manifest assumptions')
        require(all(type(v) is str and DIGEST.fullmatch(v) for v in manifest['binding'].values()),'manifest binding')
        inventory=manifest['inventory'];require(type(inventory) is list and len(inventory)<=MAX_ROWS,'inventory bound')
        inventory_keys=ordered(inventory,lambda row:key(row['key']))
        for member in inventory:
            shape(member,'key enabled');require(type(member['enabled']) is bool,'inventory eligibility')
        inventory_set=set(inventory_keys)
        attempt_keys=ordered(manifest['attempts'],lambda row:key(row['key']))
        for row in manifest['attempts']:
            count=row['count'];require(type(count) is int and 0<=count<=2**53-1,'exact attempt count')
            require(key(row['key']) in inventory_set,'attempt outside inventory');attempts[key(row['key'])]=count
        if manifest['attempts_complete']:require(attempt_keys==inventory_keys,'attempt accounting')
    kind=envelope['format'];limits=[];invocation=UNKNOWN.copy();provider=envelope['provider'];version=envelope['provider_version'];basis='UNKNOWN'
    if kind=='JUNIT_XML':
        require(envelope['media_type']=='application/xml','media type')
        native,limits=parse_junit(raw,inventory)
        rows=[dict(key=dict(namespace='NATIVE_QUALIFIED',package=k[0],target=k[1],qualified_name=k[2]),
            outcome=v['outcome'],attempts=None,retry_metadata_present=v['retry_metadata_present'],finding_count=None) for k,v in native.items()]
        if manifest is not None:invocation=manifest['invocation'];basis='COMPANION_MANIFEST'
    elif kind=='SARIF210':
        require(envelope['media_type']=='application/sarif+json','media type')
        rows,limits,invocation,provider,version=parse_sarif(raw,manifest)
        basis='UNKNOWN' if invocation==UNKNOWN else 'PAYLOAD'
    elif kind=='CARGO_SUITE':
        require(envelope['media_type']=='application/vnd.fortress.cargo-suite+json','media type')
        suite=unique_json(raw);require(manifest is not None,'controlled Cargo manifest')
        complete=suite['passed'] is True and suite['canonical_unfiltered'] is True
        rows=[]
        for enabled,ids in ((True,suite['eligible_test_ids']),(False,suite['ignored_test_ids'])):
            for test in ids:rows.append(dict(key=dict(namespace='GOVERNED_TEST_ID',package=None,target=None,qualified_name=test),
                outcome=('PASSED' if enabled else 'SKIPPED') if complete else 'UNKNOWN',attempts=None,retry_metadata_present=False,finding_count=None))
        invocation=dict(succeeded=suite['passed'],exit_code=None);basis='PAYLOAD';provider=suite['executor'];version=suite['executor_version']
    else:raise ValueError('unsupported format')
    for row in rows:
        count=attempts.get(key(row['key']))
        row['attempts']=None if row['retry_metadata_present'] and count is not None and count<=1 else count
    rows.sort(key=lambda row:order(key(row['key'])))
    require(canonical(rows)==canonical(envelope['observations']),'raw payload does not reproduce normalized rows')
    require(sorted(limits)==envelope['limitations'],'raw payload limitation mismatch')
    require(invocation==envelope['invocation'] and basis==envelope['invocation_basis'],'raw invocation mismatch')
    require(provider==envelope['provider'] and version==envelope['provider_version'],'raw producer mismatch')
    if manifest is not None and invocation['succeeded'] is not None and manifest['invocation']['succeeded'] is not None:
        require(invocation['succeeded'] is manifest['invocation']['succeeded'],'raw/companion invocation conflict')
    accounted=(manifest is not None and bool(inventory) and manifest['inventory_complete'] is True
        and manifest['filtering_known'] is True and not manifest['filters'] and not limits
        and ordered(inventory,lambda row:key(row['key']))==observed
        and all(member['enabled'] is True and row['outcome'] in ('PASSED','FAILED')
            and row['attempts']==1 and not row['retry_metadata_present'] for member,row in zip(inventory,rows)))
    return rows,accounted

def resolve(envelope,raw,expected,requirement,host):
    rows,accounted=verify(envelope,raw);manifest=envelope['run_manifest'];identity=digest(canonical(envelope))
    if envelope['format']=='SARIF210' or manifest is None:return 'NOT_EVALUABLE'
    if manifest['binding']!=expected or manifest['provider']!=requirement['provider'] or manifest['invocation_scope']!=requirement['invocation_scope']:return 'NOT_EVALUABLE'
    if identity not in host.get('admitted_envelopes',[]):return 'NOT_EVALUABLE'
    if requirement['authenticated_producer_required']:return 'NOT_EVALUABLE'
    if any(a not in host.get('accepted_assumptions',[]) for a in manifest['assumptions']):return 'NOT_EVALUABLE'
    descriptor=manifest['execution'];current=host.get('current_executions',{}).get(identity)
    if current is not None:execution(current)
    # This independent process accepts no serialized claim of freshness.
    if descriptor.get('dependencies_complete') is not True or current!=descriptor:return 'NOT_EVALUABLE'
    if any(descriptor.get(field) is None for field in ('binary_digest','tool_digest','arguments','working_directory')):return 'NOT_EVALUABLE'
    if manifest['inventory_complete'] is not True or not manifest['inventory']:return 'NOT_EVALUABLE'
    selected=[]
    for selector in requirement['selectors']:
        matches=[member['key'] for member in manifest['inventory'] if member['key']['namespace']==selector['namespace']
            and member['key']['qualified_name']==selector['qualified_name']
            and all(selector[field] is None or member['key'][field]==selector[field] for field in ('package','target'))]
        if len(matches)!=1 or key(matches[0]) in selected:return 'NOT_EVALUABLE'
        selected.append(key(matches[0]))
    if not selected:return 'NOT_EVALUABLE'
    by_key={key(row['key']):row for row in rows}
    values=[True if accounted else None,envelope['invocation']['succeeded']]
    for identity in selected:
        row=by_key.get(identity)
        if row is None or row['attempts']!=1 or row['retry_metadata_present'] or row['outcome'] not in ('PASSED','FAILED'):
            values.append(None)
        else:values.append(row['outcome']=='PASSED')
    return 'NOT_SATISFIED' if False in values else 'SATISFIED' if all(v is True for v in values) else 'NOT_EVALUABLE'

"""Independent SARIF2.1 subset reference; standard JSON parser, no Fortress imports.

Expected fixtures come from SARIF run/invocation/rule/result semantics. Tool
execution success, inventory completeness and findings are separate propositions.
"""
from provider_xml import unique_json, require, MAX_ROWS, MAX_NORMALIZED
import unicodedata

SCOPE='run:0/invocation:0'

def text(value):
    require(type(value) is str and 0<len(value.encode('utf-8'))<=65536 and
            not any(unicodedata.category(c)=='Cc' for c in value),'SARIF text')
    return value

def sequence(value,limit=MAX_ROWS):
    require(type(value) is list and len(value)<=limit,'SARIF sequence bound')
    return value

def boolean(value):
    require(value is None or type(value) is bool,'SARIF boolean')
    return value

def parse(payload,manifest):
    document=unique_json(payload)
    require(type(document) is dict and document.get('version')=='2.1.0','SARIF version')
    runs=sequence(document.get('runs'),1)
    if not runs:
        require(manifest is None,'unavailable declared run')
        return [],['SARIF_RUN_UNAVAILABLE'],dict(succeeded=None,exit_code=None),None,None
    run=runs[0];require(type(run) is dict,'SARIF run')
    tool=run['tool'];driver=tool['driver'];name=text(driver['name'])
    version=driver.get('semanticVersion')
    if version is None:version=driver.get('version')
    if version is not None:text(version)
    limitations=set()
    if version is None:limitations.add('SARIF_TOOL_VERSION_UNAVAILABLE')
    if run.get('externalPropertyFileReferences'):limitations.add('SARIF_EXTERNAL_PROPERTIES_UNRESOLVED')
    if tool.get('extensions'):limitations.add('SARIF_TOOL_EXTENSIONS_UNINTERPRETED')
    invocations=run.get('invocations')
    invocation=sequence(invocations,1)[0] if invocations else None
    outcome=dict(succeeded=None,exit_code=None)
    if invocation is None:limitations.add('SARIF_INVOCATION_SCOPE_UNRESOLVED')
    else:
        require(type(invocation) is dict,'SARIF invocation')
        outcome['succeeded']=boolean(invocation.get('executionSuccessful'))
        code=invocation.get('exitCode')
        require(code is None or type(code) is int and -(2**31)<=code<2**31,'SARIF exit code')
        outcome['exit_code']=code
        for category in ('toolExecutionNotifications','toolConfigurationNotifications'):
            for notice in sequence(invocation.get(category) or []):
                require(type(notice) is dict,'SARIF notification')
                if notice.get('level')=='error':outcome['succeeded']=False
        if invocation.get('ruleConfigurationOverrides'):limitations.add('SARIF_RULE_OVERRIDES_UNINTERPRETED')
    if outcome['succeeded'] is None:limitations.add('SARIF_INVOCATION_STATUS_UNAVAILABLE')
    rules=driver.get('rules')
    if rules is None:limitations.add('SARIF_RULE_CATALOG_UNAVAILABLE');rules=[]
    rules=sequence(rules)
    names=[];known=set()
    for rule in rules:
        rule_id=text(rule['id']);require(rule_id not in known,'duplicate SARIF rule')
        names.append(rule_id);known.add(rule_id)
        configuration=rule.get('defaultConfiguration') or {}
        if boolean(configuration.get('enabled')) is False or configuration.get('level')=='none':limitations.add('SARIF_DISABLED_RULE')
    results=run.get('results')
    if results is None:limitations.add('SARIF_RESULTS_UNAVAILABLE');results=[]
    results=sequence(results);facts={};guids=set()
    for result in results:
        require(type(result) is dict,'SARIF result')
        guid=result.get('guid')
        if guid is not None:
            text(guid);require(guid not in guids,'duplicate SARIF result GUID');guids.add(guid)
        reference=result.get('rule') or {}
        if reference.get('toolComponent'):
            limitations.add('SARIF_EXTERNAL_RULE_COMPONENT_UNINTERPRETED');continue
        rule_id=result.get('ruleId');index=result.get('ruleIndex')
        if reference.get('id') is not None:
            require(rule_id is None or rule_id==reference['id'],'SARIF rule reference conflict');rule_id=reference['id']
        if reference.get('index') is not None:
            require(index is None or index==reference['index'],'SARIF index reference conflict');index=reference['index']
        if index is not None:
            require(type(index) is int and 0<=index<len(names),'SARIF rule index')
            require(rule_id is None or rule_id==names[index],'SARIF rule ID/index conflict');rule_id=names[index]
        if rule_id is None:limitations.add('SARIF_RESULT_RULE_UNRESOLVED');continue
        text(rule_id)
        if driver.get('rules') is not None and rule_id not in known:limitations.add('SARIF_RESULT_RULE_UNREGISTERED')
        fact=facts.setdefault(rule_id,dict(failures=0,unknown=False,not_applicable=False))
        if result.get('suppressions'):
            sequence(result['suppressions']);limitations.add('SARIF_SUPPRESSED_RESULTS');fact['unknown']=True
        if result.get('baselineState')=='absent':
            limitations.add('SARIF_NONCURRENT_BASELINE_RESULT');fact['unknown']=True;continue
        kind=result.get('kind');kind='fail' if kind is None else kind
        if kind=='fail':fact['failures']+=1
        elif kind=='notApplicable':fact['not_applicable']=True
        elif kind!='pass':fact['unknown']=True;limitations.add('SARIF_RESULT_REQUIRES_INTERPRETATION')
    complete=outcome['succeeded'] is True and run.get('results') is not None and not limitations
    observations=[];charge=0
    if manifest is not None:
        require(manifest['invocation_scope']==SCOPE and manifest['provider']==name,'SARIF selected scope')
        require(version is None or manifest['provider_version']==version,'SARIF producer version')
        inventory=sequence(manifest['inventory'])
        for member in inventory:
            key=member['key'];require(key['namespace']=='NATIVE_QUALIFIED' and key['package']==name and key['target']==SCOPE,'SARIF native scope')
            rule=key['qualified_name'];require(driver.get('rules') is None or rule in known,'unregistered SARIF inventory')
            fact=facts.get(rule,{})
            count=fact.get('failures',0)
            result='FAILED' if count else 'UNKNOWN' if fact.get('unknown') else 'NOT_APPLICABLE' if fact.get('not_applicable') else 'PASSED' if complete else 'UNKNOWN'
            observations.append(dict(key=key.copy(),outcome=result,attempts=None,retry_metadata_present=False,finding_count=count if run.get('results') is not None else None))
        if version is None:version=manifest['provider_version']
    else:
        for rule,fact in sorted(facts.items()):
            if fact['failures']:
                observations.append(dict(key=dict(namespace='NATIVE_QUALIFIED',package=name,target=SCOPE if invocation is not None else None,qualified_name=rule),
                    outcome='FAILED',attempts=None,retry_metadata_present=False,finding_count=fact['failures']))
    for observation in observations:
        charge+=256+sum(len((value or '').encode('utf-8')) for value in observation['key'].values())
        require(charge<=MAX_NORMALIZED,'normalized SARIF output budget')
    return observations,sorted(limitations),outcome,name,version

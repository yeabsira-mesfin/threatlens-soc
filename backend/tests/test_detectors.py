from detectors import detect
def event(id,timestamp,kind='authentication',action='failure',ip='198.51.100.1',**kw):
    return dict(id=id,timestamp=timestamp,event_type=kind,action=action,source_ip=ip,**kw)

def test_brute_force_fifth_failure_triggers_once():
    events=[event(i+1,f'2026-10-28T12:0{i}:00Z') for i in range(6)]
    found=detect(events)
    hits=[a for a in found if a['rule_id']=='AUTH_BRUTE_FORCE']
    assert len(hits)==1
    assert hits[0]['event_id']==5

def test_different_sources_and_older_failures_do_not_trigger():
    events=[event(i+1,f'2026-10-28T12:0{i}:00Z',ip=str(i)) for i in range(5)]
    assert detect(events)==[]

def test_synthetic_geo_and_endpoint_mapping():
    items=[
       event(1,'2026-10-28T12:00:00Z',action='success',geo_label='Unexpected Region'),
       event(2,'2026-10-28T12:05:00Z',kind='endpoint',action='process_start',process='powershell -enc [synthetic]')
    ]
    techniques={a['technique'] for a in detect(items)}
    assert techniques=={'T1078','T1059.001'}

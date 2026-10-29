import os
from fastapi.testclient import TestClient
from main import app, hash_password
from storage import db

def test_role_restrictions_alert_triage_and_case_report(tmp_path,monkeypatch):
    monkeypatch.setenv('THREATLENS_DB',str(tmp_path/'soc-test.db'))
    monkeypatch.setenv('THREATLENS_SECRET','integration_test_only_secret_more_than_32_characters')
    password='synthetic-local-test-password'
    with TestClient(app) as client:
        with db() as conn:
            for username,role in [('analyst','analyst'),('viewer','viewer')]:
                conn.execute('INSERT INTO users(username,role,password_hash) VALUES(?,?,?)',
                             (username,role,hash_password(password)))
        def login(name):
            response=client.post('/api/auth/login',json={'username':name,'password':password})
            assert response.status_code==200
            return {'Authorization':'Bearer '+response.json()['token']}
        analyst=login('analyst')
        viewer=login('viewer')
        batch=[
            {'timestamp':f'2026-10-28T13:0{i}:00Z','event_type':'authentication',
             'action':'failure','source_ip':'198.51.100.99','actor':'synthetic','summary':'Failed login'}
            for i in range(5)
        ]
        assert client.post('/api/ingest',headers=viewer,json=batch).status_code==403
        ingested=client.post('/api/ingest',headers=analyst,json=batch)
        assert ingested.status_code==200
        assert ingested.json()=={'ingested':5,'new_alerts':1}
        alerts=client.get('/api/alerts',headers=analyst)
        assert alerts.status_code==200
        alert=alerts.json()['alerts'][0]
        assert alert['rule_id']=='AUTH_BRUTE_FORCE'
        assert alert['technique']=='T1110'
        triage=client.patch('/api/alerts/'+str(alert['id']),headers=analyst,
                            json={'status':'false_positive','notes':'Synthetic threshold exercise','owner':'analyst'})
        assert triage.status_code==200
        new_case=client.post('/api/cases',headers=analyst,
                             json={'title':'Analyze synthetic authentication burst','severity':'medium','alert_ids':[alert['id']]})
        assert new_case.status_code==201
        case_id=new_case.json()['id']
        report=client.get('/api/cases/'+str(case_id)+'/report',headers=viewer)
        assert report.status_code==200
        assert 'T1110' in report.text
        assert 'Synthetic evidence timeline' in report.text
        assert client.patch('/api/cases/'+str(case_id),headers=viewer,
            json={'status':'resolved','notes':'','assignee':'viewer'}).status_code==403
        assert client.patch('/api/cases/'+str(case_id),headers=analyst,
            json={'status':'resolved','notes':'Reviewed evidence','assignee':'analyst'}).status_code==200
        assert client.get('/api/summary',headers=analyst).json()['open_cases']==0

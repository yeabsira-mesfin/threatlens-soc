"""ThreatLens SOC: defensive telemetry training API with isolated local persistence."""
import os, csv, io, hashlib, hmac, secrets
from datetime import datetime, timedelta, timezone
from typing import Literal
from contextlib import asynccontextmanager
import jwt
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from storage import db, init_db
from detectors import detect

KEY = lambda: os.environ.get('THREATLENS_SECRET','')
SCHEME = HTTPBearer(auto_error=False)
def hash_password(password: str) -> str:
    salt=secrets.token_bytes(16)
    result=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,260000)
    return salt.hex()+':'+result.hex()
def verify_password(password: str, stored: str) -> bool:
    salt,digest=stored.split(':',1)
    actual=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),260000)
    return hmac.compare_digest(actual,bytes.fromhex(digest))

def actor(credentials: HTTPAuthorizationCredentials | None = Depends(SCHEME)):
    secret=KEY()
    if len(secret)<32 or not credentials:
        raise HTTPException(status_code=401,detail='Authentication required')
    try: return jwt.decode(credentials.credentials,secret,algorithms=['HS256'])
    except jwt.PyJWTError: raise HTTPException(status_code=401,detail='Invalid session')

def analyst(user=Depends(actor)):
    if user['role']!='analyst':
        with db() as conn: conn.execute('INSERT INTO audit(actor,action) VALUES(?,?)',(user['sub'],'role_access_denied'))
        raise HTTPException(status_code=403,detail='Analyst role required')
    return user

class Login(BaseModel):
    username: str=Field(min_length=2,max_length=100)
    password: str=Field(min_length=1,max_length=256)
class Event(BaseModel):
    timestamp: datetime
    event_type: Literal['authentication','firewall','web','endpoint']
    action: str=Field(min_length=1,max_length=70)
    source_ip: str=Field(default='',max_length=70)
    actor: str=Field(default='',max_length=100)
    geo_label: str=Field(default='',max_length=100)
    process: str=Field(default='',max_length=250)
    destination: str=Field(default='',max_length=120)
    summary: str=Field(default='',max_length=400)
    severity: Literal['info','low','medium','high','critical']='info'
class Triage(BaseModel):
    status: Literal['new','investigating','false_positive','resolved']
    notes: str=Field(default='',max_length=2000)
    owner: str=Field(default='',max_length=100)
class NewCase(BaseModel):
    title: str=Field(min_length=4,max_length=160)
    severity: Literal['low','medium','high','critical']='medium'
    alert_ids: list[int]=Field(default_factory=list,max_length=50)
class UpdateCase(BaseModel):
    status: Literal['open','investigating','resolved']
    notes: str=Field(default='',max_length=2000)
    assignee: str=Field(default='',max_length=100)

@asynccontextmanager
async def lifespan(app):
    init_db()
    yield
app=FastAPI(title='ThreatLens SOC',version='0.1.0',lifespan=lifespan)
@app.get('/api/health')
def health(): return {'status':'ok','mode':'synthetic'}
@app.post('/api/auth/login')
def login(item:Login):
    if len(KEY())<32: raise HTTPException(503,'Server secret not configured')
    with db() as conn:
        record=conn.execute('SELECT * FROM users WHERE username=?',(item.username,)).fetchone()
        if not record or not verify_password(item.password,record['password_hash']):raise HTTPException(401,'Invalid credentials')
        identity={'sub':record['username'],'role':record['role'],'exp':datetime.now(timezone.utc)+timedelta(hours=2)}
        return {'token':jwt.encode(identity,KEY(),algorithm='HS256'),'user':{'username':record['username'],'role':record['role']}}
@app.get('/api/summary')
def summary(_=Depends(actor)):
    with db() as conn:
        def count(sql):return conn.execute(sql).fetchone()[0]
        return {'events':count('SELECT count(*) FROM events'),'alerts':count('SELECT count(*) FROM alerts'),
                'new_alerts':count("SELECT count(*) FROM alerts WHERE status='new'"),
                'high_alerts':count("SELECT count(*) FROM alerts WHERE severity IN ('high','critical') AND status!='resolved'"),
                'open_cases':count("SELECT count(*) FROM cases WHERE status!='resolved'")}
@app.get('/api/events')
def events(q:str='',limit:int=100,_=Depends(actor)):
    with db() as conn:
        keyword='%'+q[:80]+'%'
        rows=conn.execute('SELECT * FROM events WHERE summary LIKE ? OR source_ip LIKE ? OR actor LIKE ? ORDER BY timestamp DESC,id DESC LIMIT ?',(*[keyword]*3,max(1,min(limit,500)))).fetchall()
        return {'events':[dict(row) for row in rows]}
@app.get('/api/iocs')
def search_iocs(q:str='',limit:int=100,_=Depends(actor)):
    needle=q.strip()
    if len(needle)<3 or len(needle)>100:raise HTTPException(400,'IOC query must contain 3 to 100 characters')
    with db() as conn:
        pattern='%'+needle+'%'
        rows=conn.execute('SELECT id,timestamp,event_type,action,source_ip,destination,process,summary,severity FROM events WHERE source_ip LIKE ? OR destination LIKE ? OR process LIKE ? OR summary LIKE ? ORDER BY timestamp DESC,id DESC LIMIT ?',(*[pattern]*4,max(1,min(limit,500)))).fetchall()
        return {'matches':[dict(row) for row in rows],'count':len(rows),'query':needle}
@app.get('/api/alerts')
def alerts(_=Depends(actor)):
    with db() as conn:
        rows=conn.execute('SELECT a.*,e.timestamp,e.source_ip,e.event_type FROM alerts a JOIN events e ON e.id=a.event_id ORDER BY a.id DESC LIMIT 500').fetchall()
        return {'alerts':[dict(row) for row in rows]}
@app.get('/api/cases')
def cases(_=Depends(actor)):
    with db() as conn:
        return {'cases':[dict(row) for row in conn.execute('SELECT * FROM cases ORDER BY id DESC LIMIT 100')]}
def process_ingestion(items:list[Event],username:str):
    if len(items)>1000:raise HTTPException(413,'At most 1000 events per batch')
    with db() as conn:
        for event in items:
            payload=event.model_dump()
            payload['timestamp']=event.timestamp.astimezone(timezone.utc).isoformat()
            conn.execute('INSERT INTO events(timestamp,event_type,action,source_ip,actor,geo_label,process,destination,summary,severity) VALUES(?,?,?,?,?,?,?,?,?,?)',tuple(payload[k] for k in ['timestamp','event_type','action','source_ip','actor','geo_label','process','destination','summary','severity']))
        source=[dict(row) for row in conn.execute('SELECT * FROM events ORDER BY timestamp,id')]
        findings=detect(source)
        before=conn.total_changes
        for f in findings:
            conn.execute('INSERT OR IGNORE INTO alerts(rule_id,event_id,severity,title,technique,reason) VALUES(?,?,?,?,?,?)',(f['rule_id'],f['event_id'],f['severity'],f['title'],f['technique'],f['reason']))
        after=conn.total_changes
        conn.execute('INSERT INTO audit(actor,action) VALUES(?,?)',(username,'ingest_telemetry'))
    return {'ingested':len(items),'new_alerts':after-before}
@app.post('/api/ingest')
def ingest(items:list[Event],user=Depends(analyst)): return process_ingestion(items,user['sub'])
@app.post('/api/ingest/csv')
async def ingest_csv(request:Request,user=Depends(analyst)):
    content=await request.body()
    if len(content)>250000:raise HTTPException(413,'CSV too large')
    try:
        rows=list(csv.DictReader(io.StringIO(content.decode('utf8-sig'))))
        items=[Event.model_validate(row) for row in rows]
    except (ValueError,UnicodeDecodeError) as e:raise HTTPException(400,'Invalid CSV format') from e
    return process_ingestion(items,user['sub'])
@app.patch('/api/alerts/{alert_id}')
def triage(alert_id:int,payload:Triage,user=Depends(analyst)):
    with db() as conn:
        row=conn.execute('UPDATE alerts SET status=?,notes=?,owner=? WHERE id=? RETURNING *',(payload.status,payload.notes,payload.owner,alert_id)).fetchone()
        if not row:raise HTTPException(404,'Alert not found')
        conn.execute('INSERT INTO audit(actor,action,object_id) VALUES(?,?,?)',(user['sub'],'triage_alert',alert_id))
        return {'alert':dict(row)}
@app.post('/api/cases',status_code=201)
def create_case(payload:NewCase,user=Depends(analyst)):
    with db() as conn:
        cursor=conn.execute('INSERT INTO cases(title,severity,assignee) VALUES(?,?,?)',(payload.title,payload.severity,user['sub']))
        case_id=cursor.lastrowid
        for alert_id in set(payload.alert_ids):
            if not conn.execute('SELECT id FROM alerts WHERE id=?',(alert_id,)).fetchone():raise HTTPException(400,'Unknown alert ID')
            conn.execute('INSERT INTO case_alerts(case_id,alert_id) VALUES(?,?)',(case_id,alert_id))
        conn.execute('INSERT INTO audit(actor,action,object_id) VALUES(?,?,?)',(user['sub'],'create_case',case_id))
        return {'id':case_id,'title':payload.title}
@app.patch('/api/cases/{case_id}')
def update_case(case_id:int,payload:UpdateCase,user=Depends(analyst)):
    with db() as conn:
        row=conn.execute('UPDATE cases SET status=?,notes=?,assignee=? WHERE id=? RETURNING *',(payload.status,payload.notes,payload.assignee,case_id)).fetchone()
        if not row:raise HTTPException(404,'Case not found')
        conn.execute('INSERT INTO audit(actor,action,object_id) VALUES(?,?,?)',(user['sub'],'update_case',case_id))
        return {'case':dict(row)}
@app.get('/api/cases/{case_id}/report',response_class=PlainTextResponse)
def report(case_id:int,_=Depends(actor)):
    with db() as conn:
        case=conn.execute('SELECT * FROM cases WHERE id=?',(case_id,)).fetchone()
        if not case:raise HTTPException(404,'Case not found')
        alerts=conn.execute('SELECT a.rule_id,a.title,a.technique,a.status,e.timestamp FROM case_alerts ca JOIN alerts a ON a.id=ca.alert_id JOIN events e ON e.id=a.event_id WHERE ca.case_id=? ORDER BY e.timestamp',(case_id,)).fetchall()
        lines=['# ThreatLens Investigation '+str(case_id),'', 'Title: '+case['title'],'Status: '+case['status'],'Severity: '+case['severity'],'Assignee: '+case['assignee'],'','## Synthetic evidence timeline']
        lines += ['- '+a['timestamp']+' | '+a['rule_id']+' | '+a['title']+' | MITRE '+a['technique'] for a in alerts]
        lines += ['','## Analyst notes',case['notes'] or 'No notes supplied','', 'All events are synthetic.']
        return '\n'.join(lines)

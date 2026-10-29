"""Seed deterministic local synthetic log data. Never use production logs."""
import os,json
from pathlib import Path
from main import hash_password,process_ingestion,Event
from storage import init_db,db

def seed():
    password=os.environ.get('THREATLENS_DEMO_PASSWORD','')
    if len(password)<12:raise RuntimeError('Set THREATLENS_DEMO_PASSWORD to 12+ characters')
    init_db()
    with db() as conn:
        for name,role in [('analyst','analyst'),('viewer','viewer')]:
            conn.execute('INSERT INTO users(username,role,password_hash) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash',(name,role,hash_password(password)))
        already=conn.execute('SELECT count(*) FROM events').fetchone()[0]
    if not already:
        records=json.loads((Path(__file__).parent/'synthetic_events.json').read_text())
        print(process_ingestion([Event.model_validate(x) for x in records],'seed'))
    print('Seeded synthetic analyst/viewer accounts. Password is the environment value.')
if __name__=='__main__':seed()

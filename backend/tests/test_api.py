from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)
def test_health(): assert client.get('/api/v1/health').json()['status'] == 'ok'
def test_unknown_hash_stays_unknown():
    r=client.post('/api/v1/reputation/hash',json={'sha256':'0'*64}); assert r.status_code==200; assert r.json()['status']=='unknown'

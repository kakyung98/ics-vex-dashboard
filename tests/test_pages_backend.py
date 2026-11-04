from fastapi.testclient import TestClient
from src.api_server import app,make_page


def test_pages_origin_health_and_upload_preflight():
    client=TestClient(app)
    origin='https://kakyung98.github.io'
    health=client.get('/api/health',headers={'Origin':origin})
    assert health.status_code==200 and health.json()['ok']
    assert health.headers['access-control-allow-origin']==origin
    preflight=client.options('/api/source/upload',headers={'Origin':origin,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Content-Type','Access-Control-Request-Private-Network':'true'})
    assert preflight.status_code==200
    assert preflight.headers['access-control-allow-private-network']=='true'
    assert preflight.headers['access-control-allow-origin']==origin


def test_untrusted_origin_does_not_get_cors_access():
    r=TestClient(app).options('/api/source/upload',headers={'Origin':'https://untrusted.example','Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Content-Type','Access-Control-Request-Private-Network':'true'})
    assert r.status_code==400
    assert 'access-control-allow-origin' not in r.headers
    assert 'access-control-allow-private-network' not in r.headers


def test_local_page_does_not_require_pages_bridge():
    page=make_page('analyzer')
    assert 'pages-bridge.js' not in page
    assert 'id="candidate-workspace"' in page and 'cert.html' not in page.split('<nav',1)[1].split('</nav>',1)[0]

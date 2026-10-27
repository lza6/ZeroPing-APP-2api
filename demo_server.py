#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZeroPing VPN — 逆向成果 demo server (:8907)
节点来源: APK 内 remote_config_defaults.xml 加密 emergency_node_catalog (AES-256-GCM/PBKDF2 已破)
接口:
  GET /                    -> demo.html
  GET /api/nodes           -> 节点池全量(含测活缓存)
  GET /api/health          -> 健康检查
  GET /api/xray/{node_id}  -> 节点对应的 Xray outbound 片段(可直接拼配置)
  POST /api/probe          -> 触发一轮 TCP+TLS 测活
"""
import json, os, socket, ssl, hashlib, time, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

BASE = os.path.dirname(os.path.abspath(__file__))
CAT = json.load(open(os.path.join(BASE, 'emergency_catalog_plain.json'), encoding='utf-8'))
NODES = CAT['configs'][0]['node_pool']['nodes']
CACHE = {'probe': None, 'ts': 0}

def _flat(n):
    ob = n.get('outbound') or {}
    vnext = ((ob.get('settings') or {}).get('vnext') or [{}])[0]
    ss = ob.get('streamSettings') or {}
    secss = ss.get('tlsSettings') or ss.get('realitySettings') or {}
    return ({**n, 'address': n.get('address') or vnext.get('address'),
             'port': n.get('port') or vnext.get('port'),
             'protocol': n.get('protocol') or ob.get('protocol', 'vless'),
             'network': n.get('network') or ss.get('network', ''),
             'security': n.get('security') or ss.get('security', ''),
             'server_name': n.get('server_name') or secss.get('serverName', '')})

def probe_node(n):
    n = _flat(n)
    r = {'id': n['id'], 'name': n['display_name'], 'country': n['country'], 'city': n['city'],
         'address': n['address'], 'port': n['port'], 'protocol': n['protocol'],
         'network': n['network'], 'security': n['security'], 'sni': n['server_name']}
    for port, tag in [(n['ping_port'], 'ping'), (n['port'], 'vpn')]:
        try:
            s = socket.create_connection((n['address'], port), timeout=4)
            r[tag] = {'open': True, 'ms': int((time.time()-time.time())*0) or None}
            s.close()
        except Exception:
            r[tag] = {'open': False}
    if r['vpn']['open'] and n['security'] == 'tls':
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((n['address'], n['port']), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=n['server_name']) as ts:
                    r['tls'] = {'ok': True, 'proto': ts.version(),
                                'sha256': hashlib.sha256(ts.getpeercert(binary_form=True)).hexdigest()[:16]}
        except Exception as e:
            r['tls'] = {'ok': False, 'err': type(e).__name__}
    return r

def run_probe():
    with ThreadPoolExecutor(22) as ex:
        CACHE['probe'] = list(ex.map(probe_node, NODES))
    CACHE['ts'] = time.time()
    return CACHE['probe']

def xray_outbound(n):
    if n.get('outbound'):
        return dict(n['outbound'], tag='proxy')
    out = {"protocol": "vless",
           "settings": {"vnext": [{"address": n['address'], "port": n['port'],
              "users": [{"id": n['user_id'], "encryption": "none", "flow": n.get('flow', '') or ''}]}]}}
    ss = {"network": n['network'], "security": n['security']}
    if n['security'] == 'reality':
        ss["realitySettings"] = {"serverName": n['server_name'], "fingerprint": "chrome",
                                 "publicKey": n.get('public_key', ''), "shortId": n.get('short_id', '')}
    else:
        ss["tlsSettings"] = {"allowInsecure": True, "serverName": n['server_name'],
                             "fingerprint": n.get('fingerprint', 'chrome')}
    if n['network'] == 'grpc':
        ss["grpcSettings"] = {"serviceName": n['grpc_service_name'], "authority": n['server_name']}
    elif n['network'] == 'ws':
        ss["wsSettings"] = {"path": n.get('ws_path', '/'), "headers": {"Host": n['server_name']}}
    out["streamSettings"] = ss
    return out

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == '/':
            b = open(os.path.join(BASE, 'demo.html'), 'rb').read()
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
        elif self.path == '/api/health':
            self._json({'ok': True, 'nodes': len(NODES), 'probe_cached': CACHE['ts']})
        elif self.path == '/api/nodes':
            if CACHE['probe'] and time.time()-CACHE['ts'] < 300:
                nodes = CACHE['probe']
            else:
                nodes = run_probe()
            self._json({'catalog_version': CAT['configs'][0].get('catalog_version'), 'count': len(nodes), 'nodes': nodes})
        elif m := re.match(r'/api/xray/(\d+)', self.path):
            n = next((x for x in NODES if x['id'] == m.group(1)), None)
            self._json(xray_outbound(n) if n else {'error': 'not found'}, 200 if n else 404)
        else:
            self._json({'error': 'not found'}, 404)
    def do_POST(self):
        if self.path == '/api/probe':
            self._json({'nodes': run_probe(), 'ts': CACHE['ts']})
        else:
            self._json({'error': 'not found'}, 404)

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8907
    print(f'ZeroPing demo server on :{port}, {len(NODES)} nodes')
    HTTPServer(('0.0.0.0', port), H).serve_forever()

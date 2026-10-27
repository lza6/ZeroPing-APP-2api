#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZeroPing Config API 复现客户端（2026-10-28 实测通过: 新注册 -> 66 节点目录解密成功）

协议要点（逆向自 a5.p/q/s/w0）:
  1. 客户端生成 RSA-2048 install_key，install_key_id 自拟格式 `ik_`+32hex
  2. POST /v1/active-config，body 必须含 market_iso（如 'us'，缺省或未知值会返回
     limited_unknown_market / encryption_required）
  3. 响应 {result:'ok', signature_key_id, signature, payload_protection{...}}
     payload_protection = {mode:'encrypted', enc_alg:'AES-256-GCM',
       key_wrap_alg:'RSA-OAEP-SHA256-MGF1SHA1',   # 注意 MGF1 用 SHA1
       wrapped_key_base64, nonce_base64, ciphertext_base64, tag_base64}  # urlsafe b64
  4. RSA-OAEP(SHA256, MGF1-SHA1) 解 CEK -> AESGCM 解 -> 明文 {config_version, node_pool{nodes:[...]}}

依赖: pip install cryptography
"""
import base64, json, secrets, sys, urllib.request, urllib.error, ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAINS = [
    'https://zeroping-config-api-prod-237693822618.europe-west1.run.app',
    'https://zeroping-config.64-188-63-254.sslip.io',
    'https://zeroping-prod.169-58-27-198.sslip.io',
]

def b64d(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def fetch(domain, market_iso='us'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    body = {
        'product': 'zeroping', 'platform': 'android', 'app_version': '0.1.35 (35)',
        'outbound_schema': 1, 'market_iso': market_iso,
        'supported_transports': ['grpc', 'ws', 'xhttp', 'raw'],
        'install_key': {'install_key_id': 'ik_' + secrets.token_hex(16),
                        'public_key_alg': 'RSA-OAEP-SHA256-MGF1SHA1',
                        'public_key_spki_base64': spki},
    }
    req = urllib.request.Request(domain.rstrip('/') + '/v1/active-config',
        data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                 'User-Agent': 'ZeroPing/0.1.35 (Android)'})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        resp = json.load(r)
    if resp.get('result') != 'ok':
        raise RuntimeError(f"server rejected: {resp.get('result')} {resp.get('reason_key','')}")
    pp = resp['payload_protection']
    cek = key.decrypt(b64d(pp['wrapped_key_base64']),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None))
    pt = AESGCM(cek).decrypt(b64d(pp['nonce_base64']),
                             b64d(pp['ciphertext_base64']) + b64d(pp['tag_base64']), None)
    return json.loads(pt)

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'active_config_plain.json'
    for d in DOMAINS:
        try:
            plain = fetch(d)
            json.dump(plain, open(out, 'w', encoding='utf-8'), indent=1)
            nodes = len(plain.get('node_pool', {}).get('nodes', []))
            print(f'OK {d}\n  -> {out}  version={plain.get("config_version")} nodes={nodes}')
            break
        except Exception as e:
            print(f'FAIL {d}: {e}')

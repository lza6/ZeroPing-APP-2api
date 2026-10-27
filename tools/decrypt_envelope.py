#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZeroPing obf 信封解密工具（实测验证版）
破解对象: APK res/xml/remote_config_defaults.xml 中的加密信封
  (config_api_domains_obf / emergency_node_catalog(_debug)_obf)

用法:
  python decrypt_envelope.py defaults_entries.json emergency_node_catalog_obf
  python decrypt_envelope.py <xml提取的entries json> <key名> [-o out.json]

依赖: pip install cryptography
原理:
  password = "\\n".join([product, package, cert_sha256, key, key_version, build_seed])
  PBKDF2-HMAC-SHA256(password, salt, iterations, 32B) -> AES-256-GCM(nonce, ct+tag)
  payload 外层再 base64 -> 明文 JSON
"""
import base64, json, hashlib, argparse, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PRODUCT = 'zeroping'
PACKAGE = 'com.zero.ping.vpn'
CERT_SHA256 = '8022bf589e5b5b60cbb8c6f04b851d78f89645543142cecd61782ab01b4d237f'

def decrypt_envelope(env: dict, cert=CERT_SHA256):
    salt = base64.b64decode(env['salt_base64'])
    nonce = base64.b64decode(env['nonce_base64'])
    ct = base64.b64decode(env['ciphertext_base64'])
    tag = base64.b64decode(env['tag_base64'])
    seed = env['build_seed']
    pw = '\n'.join([env.get('product', PRODUCT), env.get('package', PACKAGE),
                    cert, env['key'], env['key_version'], seed])
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, env['kdf_iterations'], dklen=32)
    pt = AESGCM(dk).decrypt(nonce, ct + tag, None)
    outer = json.loads(pt)
    if 'payload_base64' in outer:
        return json.loads(base64.b64decode(outer['payload_base64']))
    return outer

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('entries', help='remote_config_defaults.xml 提取的 {key: value} JSON')
    ap.add_argument('key', help='信封键名, 如 emergency_node_catalog_obf')
    ap.add_argument('-o', '--out', default=None)
    a = ap.parse_args()
    entries = json.load(open(a.entries, encoding='utf-8'))
    env = entries[a.key]
    if isinstance(env, str):
        env = json.loads(env.replace('&quot;', '"'))
    if env.get('protection') != 'obfuscated':
        print('非加密信封, 明文如下:'); print(json.dumps(env, indent=1, ensure_ascii=False)[:2000]); return
    try:
        plain = decrypt_envelope(env)
    except Exception as e:
        sys.exit(f'解密失败: {e}')
    out = a.out or f'{a.key}.plain.json'
    json.dump(plain, open(out, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    print(f'解密成功 -> {out}  ({len(json.dumps(plain))} bytes)')

if __name__ == '__main__':
    main()

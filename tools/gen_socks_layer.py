#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZeroPing 节点池 -> SOCKS5 转换层配置生成器
用法:
  python tools/gen_socks_layer.py --nodes data/nodes_live.json --out socks_layer --base-port 31000
输出: 每节点一份 Xray 配置 (socks inbound -> vless outbound) + manifest.json
"""
import json, os, sys, argparse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nodes', required=True)
    ap.add_argument('--out', default='socks_layer')
    ap.add_argument('--base-port', type=int, default=31000)
    a = ap.parse_args()
    nodes = json.load(open(a.nodes, encoding='utf-8'))
    os.makedirs(a.out, exist_ok=True)
    manifest = []
    for i, n in enumerate(nodes):
        ob = n.get('outbound')
        if not ob:
            continue
        cfg = {"inbounds": [{"port": a.base_port + i, "listen": "127.0.0.1",
                             "protocol": "socks", "settings": {"udp": False}}],
               "outbounds": [ob, {"protocol": "freedom"}]}
        p = os.path.join(a.out, f"cfg_{n['id']}.json")
        json.dump(cfg, open(p, 'w', encoding='utf-8'), indent=1)
        manifest.append({"id": n['id'], "name": n['display_name'], "country": n['country'],
                         "city": n.get('city', ''), "socks": f"127.0.0.1:{a.base_port + i}",
                         "xray_cfg": os.path.abspath(p)})
    json.dump(manifest, open(os.path.join(a.out, 'manifest.json'), 'w', encoding='utf-8'),
              indent=1, ensure_ascii=False)
    print(f'{len(manifest)} configs -> {a.out}/ (ports {a.base_port}..{a.base_port + len(manifest) - 1})')

if __name__ == '__main__':
    main()

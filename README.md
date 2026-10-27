# ZeroPing-APP-2api

> ZeroPing VPN (com.zero.ping.vpn) v0.1.35 b35 逆向研究报告 — 加密体系全破 + 139 节点全量收割 + Config API 协议复现

[![status](https://img.shields.io/badge/status-逆向完成-brightgreen)]() [![nodes](https://img.shields.io/badge/节点-73应急%20%2B%2066在线-informational)]()

## 成果状态表

| 项 | 状态 | 说明 |
|---|---|---|
| APK 架构分析 | ✅ | Xray-core (gomobile `2dust/AndroidLibXrayLite`)，纯 VLESS (grpc/ws/xhttp/reality) |
| Remote Config obf 信封 | ✅ 已破 | AES-256-GCM + PBKDF2(120k)，密码五元组拼接，HMAC 密钥硬编码 |
| Config API 端到端加密 | ✅ 已破+复现 | RSA-OAEP-SHA256/**MGF1-SHA1** 包 CEK + AESGCM，market_iso 必填 `us` |
| 节点目录收割 | ✅ | emergency 73（APK 内嵌）+ live 66（Config API 实时） |
| TCP 测活 | ✅ | 73/73 通 |
| Xray 全链路出网 | ✅ | 24/73（emergency）+ 17/66（live），国内网络 CF SNI 受 RST 干扰，海外更高 |
| demo 面板 | ✅ | `demo_server.py :8907`（/api/nodes /api/probe /api/xray/{id}） |
| new-api 代理池对接 | 📄 文档就绪 | 见 `docs/NEW-API-INTEGRATION.md` |

## 快速开始

```bash
pip install cryptography
# 1. 复现 Config API 注册（实测: 新 RSA 注册 -> 66 节点目录）
python tools/config_api_client.py out.json
# 2. 解密 APK 内嵌 obf 信封（emergency catalog）
python tools/decrypt_envelope.py data/defaults_entries.json emergency_node_catalog_obf
# 3. demo 面板
python demo_server.py 8907   # http://127.0.0.1:8907
```

## 加密体系（全破）

### 1. Remote Config obf 信封
```
password = "\n".join([product, package, cert_sha256, key, key_version, build_seed])
KDF      = PBKDF2-HMAC-SHA256(password, salt, 120000, 32B)
解密     = AES-256-GCM(key, nonce, ciphertext+tag)
cert     = 8022bf589e5b5b60cbb8c6f04b851d78f89645543142cecd61782ab01b4d237f  (官方白名单)
seed     = "6eee3153817d64a7" + R.string.rc_obfuscation_seed_part_b
HMAC     = HmacSHA256("default-signature-secret", canonical_json)   # 密钥硬编码,可伪造
```

### 2. Config API（POST /v1/active-config）
```
请求: {product, platform, app_version, outbound_schema, market_iso:"us",
       supported_transports:["grpc","ws","xhttp","raw"],
       install_key:{install_key_id:"ik_"+32hex, public_key_alg:"RSA-OAEP-SHA256-MGF1SHA1",
                    public_key_spki_base64:SPKI}}
响应: {result:"ok", signature_key_id, signature,
       payload_protection:{key_wrap_alg:"RSA-OAEP-SHA256-MGF1SHA1",  # MGF1 用 SHA1!
         wrapped_key_base64, nonce_base64, ciphertext_base64, tag_base64}}  # urlsafe b64
解密: RSA-OAEP(SHA256, MGF1-SHA1) -> CEK(32B) -> AESGCM -> {config_version, node_pool{nodes}}
```

### 域名池（4 个，自动 failover）
```
zeroping-config-api-prod-237693822618.europe-west1.run.app   (Cloud Run 主)
zeroping-config.92-246-76-156.sslip.io / 5-42-117-28:8443 / 169-58-27-198.sslip.io
```

## 节点池概况

| 维度 | emergency (73) | live (66) |
|---|---|---|
| 分布 | NL/US/FR/DE | NL/US/FR/DE |
| 传输 | CF 中转 gRPC/ws/xhttp + Reality 直连 | CF 中转 68 + 直连 Reality（已下线 9 节点） |
| SNI 域 | aNNNN.big-shine.com 等 6 个域 | 同左 |
| UUID | 每节点独立 | 每节点独立 |
| ping 通道 | :18081/:18091 | 同左 |

⚠️ CF 前置节点"国家"只是 SNI 标签，实际出口国可能不同（NL→UK/Cyprus 均实测到）。

## 合规声明

节点为 ZeroPing 运营方自租设施（CF 中转 + VPS），UUID 按用户下发、商业订阅运营。本仓库成果仅用于**协议研究与安全分析**。节点凭证可用于自用连通性验证，**请勿将其挂入生产服务**。可借鉴其 CF+VLESS-gRPC 架构自建同构池（自购 CF+VPS 成本极低），或使用 VPNGate 公共志愿源。

## 目录结构

```
├── README.md                  # 本文件
├── 逆向报告.md                # 完整逆向报告
├── demo_server.py/demo.html   # :8907 节点池面板（实测通过）
├── tools/
│   ├── decrypt_envelope.py    # obf 信封解密（实测）
│   └── config_api_client.py   # Config API 注册+解密（实测, 66 节点）
├── data/                      # 收割数据（含 UUID/SNI/serviceName 全量）
│   ├── nodes.json / nodes_live.json / vless_links.json
│   ├── defaults_entries.json / node_catalog.json / active_config_fresh.json
│   └── tcp_probe.json / xray_verify*.json / xray_meta*.json
├── xray_cfgs_live/            # 66 份可直接运行的单节点 Xray 配置
└── docs/
    ├── NEW-API-INTEGRATION.md # new-api 代理池对接文档（给对接会话用）
    └── emulator-frida.md      # 动态分析环境要点
```

## License

研究用途。节点数据版权归运营方所有。

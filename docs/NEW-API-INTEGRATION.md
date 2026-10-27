# ZeroPing 节点池 → new-api 代理池对接文档

> 交接对象: 负责 new-api 对接的会话。本文档自包含，无需回看逆向过程。
> 产物根目录: `D:\apk-analysis\zeroping\`，本仓库: `lza6/ZeroPing-APP-2api`

## 0. 你会拿到什么

**139 个 VLESS 节点**（73 应急 + 66 在线实时版），其中经 Xray 全链路实测可出网：
- emergency 版: 24/73（本机网络；海外网络存活率显著更高）
- live 版: 17/66

节点形式（每个都含全量凭证）:
```json
{
  "id": "1001", "display_name": "Netherlands 001", "country": "NL",
  "address": "104.18.20.94", "port": 8443,
  "user_id": "d340ed67-d0bc-4543-b9b3-a1b4570e3b8a",
  "protocol": "vless", "network": "grpc", "security": "tls",
  "server_name": "a1001.big-shine.com",
  "grpc_service_name": "zp1001grpcd7381e1d69dc7b85",
  "ping_port": 18081,
  "outbound": { ...完整 Xray outbound 对象... }
}
```

数据文件（在 `data/`）:
| 文件 | 内容 | 用途 |
|---|---|---|
| `nodes_live.json` | 66 在线节点（权威，含 outbound） | **对接首选** |
| `nodes.json` | 73 应急节点 | 备用/补充 |
| `vless_links.json` | vless:// 分享链接（含实测延迟） | 快速导入 v2rayN 等客户端 |
| `xray_cfgs_live/*.json` | 每节点完整可运行 Xray 配置 | 直接起进程用 |
| `active_config_fresh.json` | Config API 实时目录原始解密 | 定期刷新源 |

## 1. 架构：SOCKS5 转换层（同 quixsocks 模式）

new-api 的代理池吃 SOCKS5/HTTP 代理，不吃 VLESS。所以中间加一层 Xray 把 VLESS 转 SOCKS5：

```
new-api 渠道代理设置 ──► 127.0.0.1:31xxx (SOCKS5)
                              │
                        Xray 实例(每节点一个)
                              │
                        VLESS grpc/ws ──► CF CDN ──► ZeroPing 后端
```

### 一键转换配置生成

```bash
cd ZeroPing-APP-2api
python tools/gen_socks_layer.py --nodes data/nodes_live.json --out socks_layer/ --base-port 31000
```

（生成器脚本见 §5，把每个节点的 outbound 包一层 socks inbound）

### 批量启动（Windows）

```powershell
Get-ChildItem socks_layer\cfg_*.json | ForEach-Object {
  Start-Process -WindowStyle Hidden .\xray.exe -ArgumentList "run","-c",$_.FullName
}
```

每个实例监听 `127.0.0.1:31000+i`，对 new-api 就是普通 SOCKS5。

## 2. new-api 侧接入

### 方式 A: 渠道级代理（推荐先做）
渠道编辑页 → 代理设置 → 填 `socks5://127.0.0.1:31001`。适合给单一渠道固定出口。

### 方式 B: 代理池页面
new-api 已有代理池管理页（`controller/twoapi_panel.go` 拆出的 proxy-pool 模块）。把节点注册进去：

| 字段 | 值 |
|---|---|
| 名称 | `zeroping-NL-001` 等（`{国家}-{城市}-{id}`） |
| 类型 | socks5 |
| 地址 | `127.0.0.1:31000+i` |
| 测活 URL | `http://ip-api.com/line/?fields=query` |
| 测活端口 | 转换层本地端口（永远活/死取决于 Xray 进程） |

### 方式 C: 直接在池里做真实测活
对每个转换层端口走一次 `curl --socks5 127.0.0.1:PORT http://ip-api.com/line/?fields=query,country`，把出口 IP/国家写回池元数据。**注意**: CF 前置节点实际出口国 ≠ 标称国（NL→UK/Cyprus），按实测 IP 记录。

## 3. 测活与刷新

1. **本地测活**（转换层层）: 每 10min 对各 socks 端口做 Google 204 或 ip-api 检查
2. **目录刷新**（源层）: Config API 每 12h 轮换目录（`refresh_after_seconds=43200`）：
   ```bash
   python tools/config_api_client.py fresh.json   # 任意时刻重跑，拿最新 66 节点
   ```
   对比 `config_version`（`cfg-prod-p1-20260727-<ts>`，ts 变了就重新生成配置、重启 Xray）
3. **节点死亡特征**: TCP 通但空回复 = 凭证轮换；TCP 不通 = 下线。用 `xray_verify*.json` 的历史格式记录。

## 4. 已知坑（前车之鉴）

| 坑 | 处理 |
|---|---|
| 本机网络对 `*.big-shine.com` SNI 有 RST | gRPC 组大多能过；xhttp/ws 组国内基本全灭 → 优先 grpc 节点，或部署在海外 VPS 上 |
| MGF1 必须用 SHA1（不是 SHA256） | 解 CEK 时 `padding.OAEP(mgf=MGF1(SHA1), algorithm=SHA256)` |
| market_iso 缺了会被拒 | body 必须带 `market_iso: "us"` |
| urlsafe base64 无 padding | 统一 `s + '='*(-len(s)%4)` |
| 8903/8907 端口残留进程 | 重启 demo/转换层前先按 CommandLine kill 旧 xray/python |
| demo 页 UI 验证 | 用户要求必须 playwright 截图自查，不能只 curl |

## 5. 转换层生成器（gen_socks_layer.py）

```python
#!/usr/bin/env python3
# 每节点: socks inbound(:31000+i) -> 节点 outbound
import json, os, sys
nodes = json.load(open(sys.argv[sys.argv.index('--nodes')+1], encoding='utf-8'))
out = sys.argv[sys.argv.index('--out')+1]
base = int(sys.argv[sys.argv.index('--base-port')+1]) if '--base-port' in sys.argv else 31000
os.makedirs(out, exist_ok=True)
manifest = []
for i, n in enumerate(nodes):
    ob = n.get('outbound')
    if not ob: continue
    cfg = {"inbounds":[{"port":base+i,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":False}}],
           "outbounds":[ob,{"protocol":"freedom"}]}
    p = os.path.join(out, f"cfg_{n['id']}.json")
    json.dump(cfg, open(p,'w'), indent=1)
    manifest.append({"id":n['id'],"name":n['display_name'],"country":n['country'],
                     "socks":f"127.0.0.1:{base+i}","xray_cfg":p})
json.dump(manifest, open(os.path.join(out,'manifest.json'),'w'), indent=1)
print(f'{len(manifest)} configs -> {out}')
```

> 提交前请在真实环境跑通 ≥1 节点出网再入库（工具脚本必须实测验证后提交 — 团队规则）。

## 6. 凭证轮换监控（可选进阶）

Config API 目录里每个节点有 `release_id` / `config_version` / `client_params_sha256`。轮换监控:
1. cron 每 6h 跑 `config_api_client.py`
2. diff 新旧 `client_params_sha256` → UUID 变了的节点标记"需重取"
3. UUID 变化率异常高（>50%）说明运营方在轮换池 → 触发全量重建

## 7. 给对接会话的最小验收清单

- [ ] `python tools/config_api_client.py` 跑通，得到 66 节点
- [ ] `gen_socks_layer.py` 生成 66 份配置
- [ ] 至少 1 个 Xray 实例 socks 出口验证通过（ip-api 返回非本机 IP）
- [ ] new-api 代理池页能看到节点并测活
- [ ] 渠道绑定代理后，走该渠道的请求出口 IP 为节点出口

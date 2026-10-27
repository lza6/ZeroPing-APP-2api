# 动态分析环境要点（ZeroPing & 通用）

本机 Nox/MuMu 均为空壳已卸载，官方 SDK 路线可用：`D:\android-sdk`

## 环境清单
- cmdline-tools: `D:\android-sdk\cmdline-tools`
- emulator 16632760 + sysimg `google_apis x86_64-30_r11`（已下载: `sysimg30.zip`/`sysimg33.zip`）
- Hyper-V 已启用；platform-tools: `D:\android-sdk\platform-tools`
- frida-server: `D:\android-sdk\frida-server\`
- build-tools 缺失（无 aapt），AXML 解析用 Python 手写 string-pool parser 替代

## 常用流程
```powershell
# 创建/启动 AVD
avdmanager create avd -n zp -k "system-images;android-30;google_apis;x86_64"
emulator -avd zp -no-window &
adb install zeroping.apk
adb push frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
frida -U -f com.zero.ping.vpn -l hook.js
```

## ZeroPing 专项 hook 点
| 目标 | 类/方法 | 说明 |
|---|---|---|
| Config API 响应明文 | `a5.s.g` / `c5.b.b("config_envelope_decode")` | hook 返回值拿解密后目录 |
| 节点池状态 | SharedPreferences `zeroping_node_pool_state` | `adb shell run-as` 或 root 后直接读 |
| 远端 RC 值 | `a5.w0.p()` 返回的 `o4.c` | 拿最新 `emergency_node_catalog_obf` |
| Play Integrity | `h1` / `config_play_integrity` | 模拟器大概率 MEETS_BASIC_INTEGRATION 以下，需研究绕过或真机 |

## 经验
- 远程 Config fetch 需要 Firebase Installations token（FIS 注册 API key + 正确 package + SHA-1 cert 头）
- FID 必须 22 字符 base64url 字符集（`[A-Za-z0-9_-]`）
- JSON 大 payload（172KB）注意 `urllib` 默认无压缩头，手动加 `Accept-Encoding: gzip` 后用 gzip 解

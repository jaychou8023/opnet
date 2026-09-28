# OpNet 上线面板（web/）

零依赖（Python3 标准库）的小服务：**你在页面上配置一次，目标机器只跑一条命令上线。**

## 它提供什么

| 端点 | 鉴权 | 用途 |
|---|---|---|
| `GET /` | Basic Auth | 配置页：公网地址/服务端地址/token/端口范围 + 机器清单 + 一键复制 |
| `GET /api/config` `POST /api/config` | Basic Auth | 读写全局配置 |
| `GET /api/status` | Basic Auth | 探测各机器映射端口是否在线 |
| `POST /api/machines` `POST /api/machines/delete` | Basic Auth | 增删机器（新增时自动生成 32 字节随机 key） |
| `GET /i/<key>` | key | 该机器的 Linux/macOS 上线脚本（sh） |
| `GET /i/<key>.ps1` | key | 该机器的 Windows 上线脚本（PowerShell） |
| `GET /i/<key>/stop.sh` `/stop.ps1` | key | 下线脚本（只停隧道，保留客户端文件与 sshd） |
| `GET /i/<key>/uninstall.sh` `/uninstall.ps1` | key | 卸载脚本（停隧道 + 删除客户端文件，**不动 sshd**） |
| `GET /i/<key>/bin/<文件名>` | key | 客户端二进制（白名单 4 个文件，防目录穿越） |
| `GET /healthz` | 无 | 健康检查 |

安全模型：面板用密码保护；一键地址不用密码，但带有 32 字节随机 key（猜不到），且只能取到"自己那台机器"的端口和固定几个文件。

## 目录布局（服务端）

```
/opt/opnet/
├── opnet-server                  # 服务端二进制
├── bin/                          # 供分发的客户端二进制（面板从 bin_dir 读取）
│   ├── opnet-client-linux-amd64
│   ├── opnet-client-windows-amd64.exe
│   ├── opnet-client-darwin-arm64
│   └── opnet-client-darwin-amd64
└── web/
    ├── web.py                    # 本服务
    ├── install.sh.tmpl           # Linux/macOS 上线脚本模板
    ├── install.ps1.tmpl          # Windows 上线脚本模板
    ├── stop.sh.tmpl / stop.ps1.tmpl
    ├── config.json               # 配置（0600，含 token 与面板密码）
    └── opnet-web.service         # systemd 单元
```

## 部署

```bash
install -d /opt/opnet/bin /opt/opnet/web
cp release/opnet-client-* /opt/opnet/bin/
cp web/web.py web/*.tmpl web/opnet-web.service /opt/opnet/web/
cp web/config.example.json /opt/opnet/web/config.json   # 然后编辑
chmod 600 /opt/opnet/web/config.json
cp /opt/opnet/web/opnet-web.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now opnet-web
```

没放 `config.json` 时启动会自动生成一份随机 token / 随机面板密码的初始配置。

## 上线一台机器

页面上复制即可：

```bash
# Linux / macOS（需要 sudo）
curl -fsSL https://你的域名/i/<key> | sudo bash

# Windows（先以管理员身份打开 PowerShell）
irm https://你的域名/i/<key>.ps1 | iex
```

脚本做四件事：按系统/架构下载客户端 → 装并启用 sshd → 后台起隧道（`-wantport` 写死端口）→ 打印 `ssh -p <端口> <用户>@<域名>`。

## 下线 / 卸载的区别

| 操作 | 进程 | 客户端文件 | sshd（装/启用状态） |
|---|---|---|---|
| **下线** `stop.sh` / `stop.ps1` | 停止 | 保留 | 不动（仍运行、仍开机自启） |
| **卸载** `uninstall.sh` / `uninstall.ps1` | 停止 | 删除 | 不动（仍运行、仍开机自启） |

两者都**不会**碰 sshd——那是系统组件，而且关掉它很可能切断你当前正在使用的 SSH 会话
（尤其是当你正通过隧道连进去的时候）。要恢复系统原状，需手动执行：

```bash
# Linux
systemctl disable --now ssh
# macOS（关闭"远程登录"）
sudo launchctl disable system/com.openssh.sshd
```
```powershell
# Windows
Stop-Service sshd; Set-Service sshd -StartupType Manual
# 连可选功能一起卸载
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

## 已知限制

- **必须提权**：装 sshd / 开远程登录绕不过 sudo 或 UAC。
- **重启即失效**：按"临时工具"设计，不做开机自启、不做断线重连；重跑同一条命令即可。
- **同端口只能一个客户端**：端口被占用时服务端直接拒绝，不会自动改号（这是"写死端口"的前提）。
- **Windows 的 PS 5.1 对中文可能乱码**：脚本已声明 `charset=utf-8` 并设置输出编码；若仍异常，用 PowerShell 7。
- **面板暴露在公网就等于把 token 挂在网上**：请务必设置强 `admin_pass`，并考虑在反向代理层再加一层 IP 白名单。

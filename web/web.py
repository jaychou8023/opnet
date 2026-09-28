#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpNet 上线面板 —— 零依赖（Python3 标准库）的配置页 + 一键脚本分发服务。

它做三件事：
  1. 给你一个带密码的网页，用来配置公网地址/服务端地址/token，并维护"机器 → 固定端口"清单；
  2. 为每台机器生成带随机 key 的一键上线地址（sh / ps1）和下线地址；
  3. 直接分发客户端二进制（4 个平台）。

安全模型：
  * 面板本身（/ 和 /api/*）用 HTTP Basic 认证，密码在 config.json 里；
  * 一键地址 /i/<key>/... 不用密码，但 key 是 32 字节随机串，猜不到，
    且只能访问它自己那台机器的端口和固定的几个文件（白名单），不存在路径穿越。

启动: python3 web.py [--config /opt/opnet/web/config.json] [--listen 0.0.0.0:8089]
"""

import argparse
import base64
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
BIN_WHITELIST = {
    "opnet-client-linux-amd64",
    "opnet-client-windows-amd64.exe",
    "opnet-client-darwin-arm64",
    "opnet-client-darwin-amd64",
}
KEY_RE = re.compile(r"^[0-9a-f]{16,64}$")

DEFAULT_CONFIG = {
    "public_base": "http://10.168.1.4:8089",
    "server_host": "10.168.1.4",
    "control_port": 2221,
    "base_port": 2222,
    "port_slots": 100,
    "token": "",
    "admin_user": "admin",
    "admin_pass": "",
    "bin_dir": "/opt/opnet/bin",
    "machines": [],
}

_config_lock = threading.Lock()
CONFIG_PATH = os.path.join(HERE, "config.json")


# --------------------------------------------------------------------------- #
# 配置读写
# --------------------------------------------------------------------------- #
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    cfg["machines"] = [m for m in cfg.get("machines", []) if isinstance(m, dict)]
    return cfg


def save_config(cfg):
    """原子写入 + 0600 权限（里面有 token 和管理密码）"""
    d = os.path.dirname(CONFIG_PATH) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".config-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_PATH)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def public_config(cfg):
    """给前端用的配置（不泄露 token 与密码，只给掩码）"""
    return {
        "public_base": cfg["public_base"],
        "server_host": cfg["server_host"],
        "control_port": cfg["control_port"],
        "base_port": cfg["base_port"],
        "port_slots": cfg["port_slots"],
        "admin_user": cfg["admin_user"],
        "token_masked": mask(cfg.get("token", "")),
        "bin_dir": cfg["bin_dir"],
        "machines": cfg["machines"],
    }


def mask(secret):
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * 8 + secret[-4:]


def next_free_port(cfg):
    used = {int(m.get("port", 0)) for m in cfg["machines"]}
    for port in range(cfg["base_port"], cfg["base_port"] + cfg["port_slots"]):
        if port not in used:
            return port
    return 0


def find_machine(cfg, key):
    for m in cfg["machines"]:
        if hmac.compare_digest(str(m.get("key", "")), key):
            return m
    return None


# --------------------------------------------------------------------------- #
# 脚本生成
# --------------------------------------------------------------------------- #
def render(template_name, mapping):
    path = os.path.join(HERE, template_name)
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    for k, v in mapping.items():
        text = text.replace("{{%s}}" % k, str(v))
    return text


def machine_mapping(cfg, machine):
    return {
        "PUBLIC_BASE": cfg["public_base"].rstrip("/"),
        "SERVER_HOST": cfg["server_host"],
        "CONTROL_PORT": cfg["control_port"],
        "TOKEN": cfg["token"],
        "WANT_PORT": machine["port"],
        "NET_PORT": machine.get("net_port", 22),
        "KEY": machine["key"],
        "NAME": machine["name"],
    }


def port_is_open(port, timeout=0.4):
    """探测服务端本机是否已在该端口监听 —— 等价于"这台机器在线\""""
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# 页面
# --------------------------------------------------------------------------- #
PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpNet 上线面板</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 0; padding: 24px;
         background: #f6f7f9; color: #1c1e21; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 24px 0 8px; }
  .sub { color: #666; font-size: 13px; margin-bottom: 16px; }
  .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
  label { display: block; font-size: 12px; color: #555; margin-bottom: 4px; }
  input { padding: 6px 8px; border: 1px solid #ccd2d9; border-radius: 6px; font-size: 13px; width: 100%; box-sizing: border-box; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }
  button { padding: 6px 12px; border: 1px solid #ccd2d9; border-radius: 6px; background: #fff;
           font-size: 13px; cursor: pointer; }
  button.primary { background: #1677ff; border-color: #1677ff; color: #fff; }
  button.tiny { padding: 3px 8px; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid #eef1f4; vertical-align: middle; }
  th { font-size: 12px; color: #666; font-weight: 500; }
  code { background: #f2f4f7; padding: 2px 5px; border-radius: 4px; font-size: 12px; word-break: break-all; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; }
  .on { background: #e6ffec; color: #1a7f37; }
  .off { background: #f0f1f3; color: #888; }
  .row-actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .hint { font-size: 12px; color: #888; margin-top: 6px; }
  .warn { background: #fff8e6; border: 1px solid #ffe08a; padding: 10px 12px; border-radius: 8px; font-size: 13px; }
  .toast { position: fixed; right: 20px; bottom: 20px; background: #1c1e21; color: #fff; padding: 8px 14px;
           border-radius: 8px; font-size: 13px; opacity: 0; transition: opacity .2s; pointer-events: none; }
  .toast.show { opacity: 1; }
</style>
</head>
<body>
<h1>OpNet 上线面板</h1>
<div class="sub">配置一次，之后每台机器只跑一条命令即可上线。端口范围 <!--VERSION-->
 　<span style="color:#b26a00">提示：用 http:// 访问时浏览器会禁止自动复制，「复制」会退化为「已选中，按 Ctrl/⌘+C」；用 https:// 访问则是一键复制。</span></div>

<div id="warnbox"><!--WARN--></div>

<div class="card">
  <h2 style="margin-top:0">全局配置</h2>
  <div class="grid">
    <div><label>公网地址（脚本与二进制下载用，含 https://）</label><input id="public_base" value="<!--PUBLIC_BASE-->"></div>
    <div><label>服务端地址（客户端连接用，域名或 IP）</label><input id="server_host" value="<!--SERVER_HOST-->"></div>
    <div><label>控制端口</label><input id="control_port" type="number" value="<!--CONTROL_PORT-->"></div>
    <div><label>映射端口基址</label><input id="base_port" type="number" value="<!--BASE_PORT-->"></div>
    <div><label>端口槽位数</label><input id="port_slots" type="number" value="<!--PORT_SLOTS-->"></div>
    <div><label>Token（留空表示不修改）</label><input id="token" placeholder="********"></div>
    <div><label>面板密码（留空表示不修改）</label><input id="admin_pass" type="password" placeholder="********"></div>
    <div><label>二进制目录</label><input id="bin_dir" value="<!--BIN_DIR-->"></div>
  </div>
  <div class="hint">当前 token: <code><!--TOKEN_MASK--></code></div>
  <div style="margin-top:12px"><button class="primary" onclick="saveConfig()">保存配置</button></div>
</div>

<div class="card">
  <h2 style="margin-top:0">机器清单</h2>
  <table>
    <thead><tr><th>机器</th><th>映射端口</th><th>本机端口</th><th>状态</th><th>一键上线</th><th></th></tr></thead>
    <tbody><!--ROWS--></tbody>
  </table>
  <div class="grid" style="margin-top:14px">
    <div><label>新增机器名称</label><input id="new_name" placeholder="例如 mac-mini / win-pc"></div>
    <div><label>映射端口</label><input id="new_port" type="number" placeholder="<!--NEXT_PORT-->"></div>
    <div><label>要暴露的本机端口</label><input id="new_netport" type="number" value="22"></div>
    <div style="display:flex;align-items:flex-end"><button class="primary" onclick="addMachine()">添加机器</button></div>
  </div>
  <div class="hint">端口必须落在 <!--RANGE--> 之间；被占用的端口服务端会直接拒绝，不会自动改号。</div>
</div>

<div class="card" id="manual" style="display:none;border-color:#1677ff">
  <label>浏览器不允许自动复制（当前是 http:// 非安全上下文），命令已为你选中 —— 请直接按 Ctrl / ⌘ + C</label>
  <input id="manualText" readonly onclick="this.select()"
         style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px">
  <div style="margin-top:8px"><button onclick="closeManual()">关闭</button></div>
</div>

<div class="toast" id="toast"></div>

<script>
const BASE = "<!--BASE-->";
// 很多精简系统只有 wget 没有 curl，所以默认命令两者都兼容
const CMD_SH = k => '(command -v curl >/dev/null && curl -fsSL ' + BASE + '/i/' + k + ' || wget -qO- ' + BASE + '/i/' + k + ') | sudo bash';
const CMD_PS = k => 'irm ' + BASE + '/i/' + k + '.ps1 | iex';
const CMD_STOP_SH = k => '(command -v curl >/dev/null && curl -fsSL ' + BASE + '/i/' + k + '/stop.sh || wget -qO- ' + BASE + '/i/' + k + '/stop.sh) | sudo bash';
const CMD_STOP_PS = k => 'irm ' + BASE + '/i/' + k + '/stop.ps1 | iex';

function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1600);}

// 复制：navigator.clipboard 只在 HTTPS / localhost 存在，
// 用 http://内网IP 打开时必须退回到 execCommand，再不行就弹出可全选的输入框
function legacyCopy(text){
  try{
    const ta=document.createElement('textarea');
    ta.value=text; ta.setAttribute('readonly','');
    ta.style.position='fixed'; ta.style.top='-1000px'; ta.style.left='-1000px';
    document.body.appendChild(ta);
    ta.focus(); ta.select(); ta.setSelectionRange(0, text.length);
    const ok=document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  }catch(e){ return false; }
}
function showManual(text){
  const box=document.getElementById('manual');
  const inp=document.getElementById('manualText');
  inp.value=text; box.style.display='block';
  inp.focus(); inp.select();
  box.scrollIntoView({block:'nearest'});
}
function closeManual(){ document.getElementById('manual').style.display='none'; }
function copy(text){
  if(window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(
      ()=>toast('已复制'),
      ()=>{ if(legacyCopy(text)) toast('已复制'); else showManual(text); }
    );
    return;
  }
  if(legacyCopy(text)){ toast('已复制'); return; }
  showManual(text);
}

async function api(path, body){
  const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body||{})});
  const j = await r.json().catch(()=>({ok:false,error:'响应解析失败'}));
  if(!r.ok || j.ok===false){ toast('失败: ' + (j.error||r.status)); return null; }
  return j;
}

async function saveConfig(){
  const body = {
    public_base: document.getElementById('public_base').value.trim(),
    server_host: document.getElementById('server_host').value.trim(),
    control_port: parseInt(document.getElementById('control_port').value,10),
    base_port: parseInt(document.getElementById('base_port').value,10),
    port_slots: parseInt(document.getElementById('port_slots').value,10),
    bin_dir: document.getElementById('bin_dir').value.trim()
  };
  const tk = document.getElementById('token').value.trim();
  const pw = document.getElementById('admin_pass').value;
  if(tk) body.token = tk;
  if(pw) body.admin_pass = pw;
  if(await api('/api/config', body)){ toast('已保存'); setTimeout(()=>location.reload(), 700); }
}

async function addMachine(){
  const name = document.getElementById('new_name').value.trim();
  const port = parseInt(document.getElementById('new_port').value,10);
  const netport = parseInt(document.getElementById('new_netport').value,10) || 22;
  if(!name){ toast('请填机器名称'); return; }
  if(await api('/api/machines', {name, port, net_port: netport})){ toast('已添加'); setTimeout(()=>location.reload(), 700); }
}

async function delMachine(name){
  if(!confirm('删除机器 ' + name + '？其上线地址将立即失效。')) return;
  if(await api('/api/machines/delete', {name})){ toast('已删除'); setTimeout(()=>location.reload(), 700); }
}

async function refreshStatus(){
  const r = await fetch('/api/status'); const j = await r.json();
  for(const [name, online] of Object.entries(j.machines||{})){
    const el = document.querySelector('[data-status="'+CSS.escape(name)+'"]');
    if(el){ el.className = 'pill ' + (online?'on':'off'); el.textContent = online?'在线':'离线'; }
  }
}
setInterval(refreshStatus, 5000); refreshStatus();
</script>
</body>
</html>
"""


def render_rows(cfg):
    if not cfg["machines"]:
        return '<tr><td colspan="6" style="color:#888">还没有机器，先在下面添加一台。</td></tr>'
    base = cfg["public_base"].rstrip("/")
    rows = []
    for m in cfg["machines"]:
        name = str(m["name"])
        online = port_is_open(m["port"])
        rows.append(
            "<tr>"
            "<td><b>%s</b></td>"
            '<td><code>%s</code></td>'
            "<td>%s</td>"
            '<td><span class="pill %s" data-status="%s">%s</span></td>'
            '<td><div class="row-actions">'
            '<button class="tiny" onclick="copy(CMD_SH(\'%s\'))">复制 Linux/mac</button>'
            '<button class="tiny" onclick="copy(CMD_PS(\'%s\'))">复制 Windows</button>'
            '<button class="tiny" onclick="showManual(CMD_SH(\'%s\'))">查看</button>'
            '<button class="tiny" onclick="copy(CMD_STOP_SH(\'%s\'))">复制下线(sh)</button>'
            '<button class="tiny" onclick="copy(CMD_STOP_PS(\'%s\'))">复制下线(ps1)</button>'
            "</div></td>"
            '<td><div class="row-actions">'
            '<button class="tiny" onclick="delMachine(\'%s\')">删除</button>'
            "</div></td>"
            "</tr>"
            % (name, m["port"], m.get("net_port", 22),
               "on" if online else "off", name, "在线" if online else "离线",
               m["key"], m["key"], m["key"], m["key"], m["key"], name)
        )
    return "\n".join(rows)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "opnet-panel"
    cfg = None

    # ---------- 工具 ----------
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send_text(self, code, body, ctype="text/plain; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_json(self, code, obj):
        self.send_text(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def auth_ok(self):
        cfg = self.cfg
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header[6:]).decode("utf-8")
        except Exception:
            return False
        user, _, pw = raw.partition(":")
        ok_user = hmac.compare_digest(user, str(cfg.get("admin_user", "")))
        ok_pass = hmac.compare_digest(pw, str(cfg.get("admin_pass", "")))
        return ok_user and ok_pass

    def require_auth(self):
        if self.auth_ok():
            return True
        self.send_text(401, "需要登录", extra={"WWW-Authenticate": 'Basic realm="opnet"'})
        return False

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    # ---------- 路由 ----------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self.send_text(200, "ok")
        if path == "/favicon.ico":
            return self.send_text(204, "")
        if path in ("/", "/index.html"):
            if not self.require_auth():
                return
            return self.serve_page()
        if path == "/api/config":
            if not self.require_auth():
                return
            return self.send_json(200, public_config(self.cfg))
        if path == "/api/status":
            if not self.require_auth():
                return
            return self.send_json(200, {"machines": {
                m["name"]: port_is_open(m["port"]) for m in self.cfg["machines"]}})
        if path.startswith("/i/"):
            return self.serve_key_path(path)
        return self.send_text(404, "not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.send_text(404, "not found")
        if not self.require_auth():
            return
        body = self.read_json()

        if path == "/api/config":
            with _config_lock:
                cfg = load_config()
                for k in ("public_base", "server_host", "bin_dir", "admin_user", "admin_pass", "token"):
                    if k in body and isinstance(body[k], str) and body[k].strip() != "":
                        cfg[k] = body[k].strip()
                for k in ("control_port", "base_port", "port_slots"):
                    if k in body and str(body[k]).isdigit():
                        cfg[k] = int(body[k])
                if not cfg.get("admin_pass"):
                    return self.send_json(400, {"ok": False, "error": "面板密码不能为空"})
                save_config(cfg)
                self.cfg = cfg
            return self.send_json(200, {"ok": True})

        if path == "/api/machines":
            name = str(body.get("name", "")).strip()
            net_port = body.get("net_port", 22)
            if not name:
                return self.send_json(400, {"ok": False, "error": "机器名称不能为空"})
            with _config_lock:
                cfg = load_config()
                if any(m["name"] == name for m in cfg["machines"]):
                    return self.send_json(400, {"ok": False, "error": "同名机器已存在"})
                try:
                    port = int(body.get("port") or next_free_port(cfg))
                    net_port = int(net_port)
                except (TypeError, ValueError):
                    return self.send_json(400, {"ok": False, "error": "端口必须是数字"})
                lo, hi = cfg["base_port"], cfg["base_port"] + cfg["port_slots"] - 1
                if not (lo <= port <= hi):
                    return self.send_json(400, {"ok": False, "error": "映射端口必须在 %d-%d 之间" % (lo, hi)})
                if any(int(m["port"]) == port for m in cfg["machines"]):
                    return self.send_json(400, {"ok": False, "error": "端口 %d 已分配给其他机器" % port})
                if not (1 <= net_port <= 65535):
                    return self.send_json(400, {"ok": False, "error": "本机端口非法"})
                cfg["machines"].append({
                    "name": name, "key": secrets.token_hex(16), "port": port, "net_port": net_port})
                save_config(cfg)
                self.cfg = cfg
            return self.send_json(200, {"ok": True, "port": port})

        if path == "/api/machines/delete":
            name = str(body.get("name", "")).strip()
            with _config_lock:
                cfg = load_config()
                before = len(cfg["machines"])
                cfg["machines"] = [m for m in cfg["machines"] if m["name"] != name]
                if len(cfg["machines"]) == before:
                    return self.send_json(404, {"ok": False, "error": "机器不存在"})
                save_config(cfg)
                self.cfg = cfg
            return self.send_json(200, {"ok": True})

        return self.send_text(404, "not found")

    # ---------- 具体处理 ----------
    def serve_page(self):
        cfg = self.cfg

        warn = ""
        if not cfg.get("token"):
            warn = ('<div class="card warn">还没设置 token：脚本会拿空 token 去认证，服务端会拒绝。'
                    '请填入与服务端 <code>-token</code> 一致的值。</div>')

        replacements = {
            "<!--ROWS-->": render_rows(cfg),
            "<!--WARN-->": warn,
            "<!--TOKEN_MASK-->": mask(cfg.get("token", "")) or "（未设置）",
            "<!--NEXT_PORT-->": str(next_free_port(cfg) or ""),
            "<!--RANGE-->": "%d-%d" % (cfg["base_port"], cfg["base_port"] + cfg["port_slots"] - 1),
            "<!--VERSION-->": "端口范围 %d-%d" % (
                cfg["base_port"], cfg["base_port"] + cfg["port_slots"] - 1),
            "<!--BASE-->": cfg["public_base"].rstrip("/"),
            "<!--PUBLIC_BASE-->": cfg["public_base"],
            "<!--SERVER_HOST-->": cfg["server_host"],
            "<!--CONTROL_PORT-->": str(cfg["control_port"]),
            "<!--BASE_PORT-->": str(cfg["base_port"]),
            "<!--PORT_SLOTS-->": str(cfg["port_slots"]),
            "<!--BIN_DIR-->": cfg["bin_dir"],
        }
        html = PAGE
        for marker, value in replacements.items():
            html = html.replace(marker, str(value))
        return self.send_text(200, html, "text/html; charset=utf-8")

    def serve_key_path(self, path):
        cfg = self.cfg
        parts = [p for p in path.split("/") if p != ""]  # ['i', key, maybe...]
        if len(parts) < 2:
            return self.send_text(404, "not found")

        key = parts[1]
        rest = parts[2:]

        # /i/<key>.ps1
        ps1 = False
        if key.endswith(".ps1"):
            key, ps1 = key[:-4], True
        if not KEY_RE.match(key):
            return self.send_text(404, "not found")

        machine = find_machine(cfg, key)
        if not machine:
            return self.send_text(404, "该上线地址已失效（机器可能已被删除）")

        # /i/<key>/bin/<file>
        if rest and rest[0] == "bin":
            if len(rest) != 2 or rest[1] not in BIN_WHITELIST:
                return self.send_text(404, "not found")
            file_path = os.path.join(cfg["bin_dir"], rest[1])
            if not os.path.isfile(file_path):
                return self.send_text(404, "客户端二进制缺失：%s（请在服务端放置）" % rest[1])
            with open(file_path, "rb") as fh:
                return self.send_text(200, fh.read(), "application/octet-stream")

        # /i/<key>/stop.sh  |  /i/<key>/stop.ps1
        if rest and rest[0].startswith("stop"):
            if rest[0].endswith(".ps1") or ps1:
                return self.send_text(200, render("stop.ps1.tmpl", machine_mapping(cfg, machine)),
                                      "text/plain; charset=utf-8")
            return self.send_text(200, render("stop.sh.tmpl", machine_mapping(cfg, machine)),
                                  "text/plain; charset=utf-8")

        # /i/<key>  |  /i/<key>.ps1
        if ps1:
            return self.send_text(200, render("install.ps1.tmpl", machine_mapping(cfg, machine)),
                                  "text/plain; charset=utf-8")
        return self.send_text(200, render("install.sh.tmpl", machine_mapping(cfg, machine)),
                              "text/plain; charset=utf-8")


def main():
    global CONFIG_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=CONFIG_PATH)
    ap.add_argument("--listen", default="0.0.0.0:8089")
    args = ap.parse_args()

    CONFIG_PATH = os.path.abspath(args.config)
    if not os.path.exists(CONFIG_PATH):
        cfg = dict(DEFAULT_CONFIG)
        cfg["token"] = secrets.token_urlsafe(24)
        cfg["admin_pass"] = secrets.token_urlsafe(12)
        save_config(cfg)
        print("已生成初始配置 %s（内含随机 token 和面板密码，请查看）" % CONFIG_PATH, flush=True)

    Handler.cfg = load_config()
    host, _, port = args.listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    print("OpNet 面板已启动: http://%s:%s  (配置: %s)" % (host, port, CONFIG_PATH), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

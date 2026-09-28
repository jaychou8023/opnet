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
_config_mtime = 0.0
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


def publish_config(cfg):
    """保存到磁盘，并让**后续所有请求**立即看到新配置。

    NOTE: 这里必须写类属性 Handler.cfg。每个 HTTP 请求都会新建一个 handler 实例，
    写 self.cfg 只影响当前这一个请求对象，下一个请求读到的还是启动时的旧配置
    —— 表现为"保存成功但页面/脚本没变化，只有重启服务才生效"。
    """
    global _config_mtime
    save_config(cfg)
    Handler.cfg = cfg
    try:
        _config_mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        _config_mtime = 0.0


def current_config():
    """读取当前配置；若 config.json 被外部改动（手工编辑/上传）则自动重新加载"""
    global _config_mtime
    with _config_lock:
        try:
            mtime = os.path.getmtime(CONFIG_PATH)
        except OSError:
            mtime = 0.0
        if Handler.cfg is None or mtime != _config_mtime:
            Handler.cfg = load_config()
            _config_mtime = mtime
        return Handler.cfg


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
  :root{
    color-scheme: light dark;
    --bg:#f4f5f7; --card:#fff; --line:#e4e7ec; --line-soft:#f1f3f6;
    --text:#16181d; --muted:#6b7280; --brand:#2f6fed; --brand-ink:#fff; --brand-soft:#eef4ff;
    --ok:#0f9d58; --ok-soft:#e7f7ee; --off:#98a1ae; --off-soft:#f0f2f5;
    --warn-bg:#fff8e6; --warn-line:#ffe08a; --warn-ink:#8a5a00;
    --danger:#d92d20; --radius:12px;
    --shadow:0 1px 2px rgba(16,24,40,.04), 0 1px 3px rgba(16,24,40,.06);
  }
  @media (prefers-color-scheme: dark){
    :root{ --bg:#0f1115; --card:#171a21; --line:#262b35; --line-soft:#1f242d;
           --text:#e8eaee; --muted:#98a1b0; --brand:#4b8bf5; --brand-soft:#1b2740;
           --ok:#3ecf8e; --ok-soft:#12301f; --off:#7d8798; --off-soft:#1e232c;
           --warn-bg:#2c2411; --warn-line:#5c4a15; --warn-ink:#e2c07a; --shadow:none; }
  }
  *{ box-sizing:border-box; }
  body{ margin:0; padding:28px 20px 64px; background:var(--bg); color:var(--text);
        font:14px/1.55 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif; }
  .wrap{ max-width:1100px; margin:0 auto; }
  h1{ font-size:22px; margin:0 0 6px; letter-spacing:.2px; }
  .sub{ color:var(--muted); font-size:13px; margin-bottom:18px; }
  .card{ background:var(--card); border:1px solid var(--line); border-radius:var(--radius);
         padding:18px; margin-bottom:16px; box-shadow:var(--shadow); }
  .card > h2{ font-size:14px; font-weight:600; margin:0 0 14px; display:flex;
              align-items:center; justify-content:space-between; gap:10px; }
  .count{ font-size:12px; font-weight:400; color:var(--muted); }
  .subhead{ font-size:12px; color:var(--muted); margin:16px 0 8px; }
  .subhead:first-of-type{ margin-top:0; }
  label{ display:block; font-size:12px; color:var(--muted); margin-bottom:5px; }
  input{ font:inherit; font-size:13px; padding:7px 10px; width:100%; color:var(--text);
         background:var(--card); border:1px solid var(--line); border-radius:9px; }
  input:focus{ outline:none; border-color:var(--brand); box-shadow:0 0 0 3px var(--brand-soft); }
  .fieldgrid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; }

  .btn{ font:inherit; font-size:13px; padding:7px 13px; border-radius:9px; cursor:pointer; white-space:nowrap;
        border:1px solid var(--line); background:var(--card); color:var(--text);
        transition:background .12s,border-color .12s,color .12s,transform .06s; }
  .btn:hover{ background:var(--line-soft); }
  .btn:active{ transform:translateY(1px); }
  .btn-primary{ background:var(--brand); border-color:var(--brand); color:var(--brand-ink); font-weight:500; }
  .btn-primary:hover{ background:var(--brand); filter:brightness(1.07); }
  .btn-ghost{ border-color:transparent; background:transparent; color:var(--muted); }
  .btn-ghost:hover{ background:var(--line-soft); color:var(--text); }
  .btn-danger:hover{ color:var(--danger); }
  .btn.copied{ background:var(--ok-soft); border-color:transparent; color:var(--ok); font-weight:500; }

  .machines{ display:grid; grid-template-columns:repeat(auto-fill,minmax(410px,1fr)); gap:14px; }
  @media (max-width:600px){ .machines{ grid-template-columns:1fr; } }
  .mcard{ border:1px solid var(--line); border-radius:var(--radius); padding:16px;
          display:flex; flex-direction:column; gap:13px; background:var(--card); }
  .mhead{ display:flex; align-items:center; justify-content:space-between; gap:10px; }
  .mname{ font-size:15px; font-weight:600; word-break:break-all; }
  .mmeta{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; font-size:13px; color:var(--muted); }
  .chip{ background:var(--line-soft); border-radius:7px; padding:3px 9px; }
  .chip b{ color:var(--text); font-variant-numeric:tabular-nums; }
  .pill{ display:inline-flex; align-items:center; gap:6px; font-size:12px;
         padding:3px 10px; border-radius:999px; white-space:nowrap; }
  .pill .dot{ width:6px; height:6px; border-radius:50%; background:currentColor; }
  .pill.on{ background:var(--ok-soft); color:var(--ok); }
  .pill.off{ background:var(--off-soft); color:var(--off); }
  .group{ border-top:1px dashed var(--line); padding-top:12px; }
  .gtitle{ font-size:12px; color:var(--muted); margin-bottom:9px; display:flex; align-items:center; gap:8px; }
  .gtag{ background:var(--brand-soft); color:var(--brand); border-radius:5px; padding:1px 7px; font-size:11px; }
  .btnrow{ display:flex; gap:8px; flex-wrap:wrap; }
  .mfoot{ border-top:1px dashed var(--line); padding-top:11px; display:flex; justify-content:flex-end; }
  .empty{ border:1px dashed var(--line); border-radius:var(--radius); padding:30px 0;
          text-align:center; color:var(--muted); font-size:13px; }
  .addform{ display:grid; grid-template-columns:1.3fr .8fr .8fr auto; gap:12px; align-items:end;
            border-top:1px dashed var(--line); margin-top:18px; padding-top:18px; }
  @media (max-width:660px){ .addform{ grid-template-columns:1fr 1fr; } }
  .hint{ font-size:12px; color:var(--muted); margin-top:10px; }
  .warn{ background:var(--warn-bg); border:1px solid var(--warn-line); color:var(--warn-ink);
         padding:11px 14px; border-radius:10px; font-size:13px; }
  code{ background:var(--line-soft); padding:2px 6px; border-radius:5px;
        font:12px ui-monospace,Menlo,Consolas,monospace; }
  .manual{ border-color:var(--brand); }
  .mhead2{ display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
  .mrow{ margin-bottom:10px; }
  .mlabel{ font-size:12px; color:var(--muted); margin-bottom:5px; }
  .minput{ font:12px ui-monospace,Menlo,Consolas,monospace; }
  .toast{ position:fixed; left:50%; bottom:26px; transform:translateX(-50%) translateY(8px);
          background:#16181d; color:#fff; padding:9px 16px; border-radius:10px; font-size:13px;
          opacity:0; transition:opacity .18s,transform .18s; pointer-events:none; }
  .toast.show{ opacity:1; transform:translateX(-50%) translateY(0); }
</style>
</head>
<body>
<div class="wrap">
<h1>OpNet 上线面板</h1>
<div class="sub">配置一次，之后每台机器只跑一条命令即可上线。端口范围 <!--VERSION--></div>

<div id="warnbox"><!--WARN--></div>

<div class="card">
  <h2>全局配置</h2>
  <div class="subhead">对外地址（会写进每台机器的一键命令里）</div>
  <div class="fieldgrid">
    <div><label>公网地址（脚本与二进制下载用，含 https://）</label><input id="public_base" value="<!--PUBLIC_BASE-->"></div>
    <div><label>服务端地址（客户端连接用，域名或 IP）</label><input id="server_host" value="<!--SERVER_HOST-->"></div>
  </div>
  <div class="subhead">端口范围</div>
  <div class="fieldgrid">
    <div><label>控制端口</label><input id="control_port" type="number" value="<!--CONTROL_PORT-->"></div>
    <div><label>映射端口基址</label><input id="base_port" type="number" value="<!--BASE_PORT-->"></div>
    <div><label>端口槽位数</label><input id="port_slots" type="number" value="<!--PORT_SLOTS-->"></div>
  </div>
  <div class="subhead">安全与存储</div>
  <div class="fieldgrid">
    <div><label>Token（留空表示不修改）</label><input id="token" placeholder="********"></div>
    <div><label>面板密码（留空表示不修改）</label><input id="admin_pass" type="password" placeholder="********"></div>
    <div><label>二进制目录</label><input id="bin_dir" value="<!--BIN_DIR-->"></div>
  </div>
  <div class="hint">当前 token：<code><!--TOKEN_MASK--></code></div>
  <div style="margin-top:14px"><button class="btn btn-primary" onclick="saveConfig()">保存配置</button></div>
</div>

<div class="card">
  <h2>机器清单 <span class="count" id="mcount"></span></h2>
  <div class="machines" id="machines"></div>

  <div class="addform">
    <div><label>新增机器名称</label><input id="new_name" placeholder="例如 mac-mini / win-pc"></div>
    <div><label>映射端口</label><input id="new_port" type="number" placeholder="<!--NEXT_PORT-->"></div>
    <div><label>要暴露的本机端口</label><input id="new_netport" type="number" value="22"></div>
    <div><button class="btn btn-primary" onclick="addMachine()">添加机器</button></div>
  </div>
  <div class="hint">端口必须落在 <!--RANGE--> 之间；被占用的端口服务端会直接拒绝，不会自动改号。<br>
    <b>下线</b>只停隧道（客户端文件与 sshd 保留，下次上线更快）；<b>卸载</b>会停隧道并删除客户端文件，但都不会动 sshd。</div>
</div>

<div class="card manual" id="manual" style="display:none">
  <div class="mhead2">
    <strong id="manualTitle">手动复制</strong>
    <button class="btn btn-ghost" onclick="closeManual()">关闭</button>
  </div>
  <div id="manualList"></div>
  <div class="hint">浏览器不允许自动复制时（http:// 非安全上下文），命令已为你选中，直接按 Ctrl / ⌘ + C 即可。</div>
</div>

<div class="toast" id="toast"></div>
</div>

<script>
const BASE = "<!--BASE-->";
const MACHINES = <!--MACHINES-->;

// 很多精简系统只有 wget 没有 curl，所以两者都试；但只在"命令不存在"时才切换，
// 不用 || 串联——否则 curl 真的报错（如 400）时会再抛一个 "wget: command not found"，误导排查
const FETCH_CMD = url => 'if command -v curl >/dev/null 2>&1; then curl -fsSL ' + url +
  '; elif command -v wget >/dev/null 2>&1; then wget -qO- ' + url +
  '; else echo "需要 curl 或 wget，请先安装" >&2; exit 1; fi';
const CMD_SH      = k => FETCH_CMD(BASE + '/i/' + k) + ' | sudo bash';
const CMD_STOP_SH = k => FETCH_CMD(BASE + '/i/' + k + '/stop.sh') + ' | sudo bash';
const CMD_UNINSTALL_SH = k => FETCH_CMD(BASE + '/i/' + k + '/uninstall.sh') + ' | sudo bash';
const CMD_PS      = k => 'irm ' + BASE + '/i/' + k + '.ps1 | iex';
const CMD_STOP_PS = k => 'irm ' + BASE + '/i/' + k + '/stop.ps1 | iex';
const CMD_UNINSTALL_PS = k => 'irm ' + BASE + '/i/' + k + '/uninstall.ps1 | iex';

const CMDS_UNIX = { on: CMD_SH, off: CMD_STOP_SH, uninstall: CMD_UNINSTALL_SH };
const CMDS_WIN  = { on: CMD_PS, off: CMD_STOP_PS, uninstall: CMD_UNINSTALL_PS };

function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1600);}
function el(tag, cls, text){const e=document.createElement(tag); if(cls) e.className=cls; if(text!=null) e.textContent=text; return e;}

// 复制三层降级：安全上下文剪贴板 → execCommand → 弹出可全选输入框
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
async function copyText(text){
  if(window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText){
    try{ await navigator.clipboard.writeText(text); return true; }catch(e){}
  }
  return legacyCopy(text);
}
function showManual(title, items){
  document.getElementById('manualTitle').textContent = title;
  const list = document.getElementById('manualList');
  list.innerHTML = '';
  items.forEach(it=>{
    const row = el('div','mrow');
    row.appendChild(el('div','mlabel', it.label));
    const inp = el('input','minput');
    inp.readOnly = true; inp.value = it.text;
    inp.onclick = () => inp.select();
    row.appendChild(inp);
    list.appendChild(row);
  });
  const box = document.getElementById('manual');
  box.style.display = 'block';
  const first = list.querySelector('input');
  if(first){ first.focus(); first.select(); }
  box.scrollIntoView({block:'nearest'});
}
function closeManual(){ document.getElementById('manual').style.display='none'; }

function copyBtn(label, group, cls, getText){
  const b = el('button','btn ' + (cls||''), label);
  b.onclick = async () => {
    const text = getText();
    const ok = await copyText(text);
    if(!ok){ showManual(group + ' · 手动复制', [{label:'命令（已选中，按 Ctrl/⌘+C）', text}]); return; }
    b.classList.add('copied'); b.textContent = '已复制 ✓';
    setTimeout(()=>{ b.classList.remove('copied'); b.textContent = label; }, 1300);
  };
  return b;
}
function viewBtn(group, shOn, shOff, psOn, psOff){
  const b = el('button','btn btn-ghost','查看命令');
  b.onclick = () => showManual(group, [
    {label:'Linux / macOS · 上线命令', text: shOn},
    {label:'Linux / macOS · 下线命令', text: shOff},
    {label:'Windows · 上线命令（管理员 PowerShell）', text: psOn},
    {label:'Windows · 下线命令（管理员 PowerShell）', text: psOff},
  ]);
  return b;
}

function osGroup(title, tag, cmds, m, manualItems){
  const g = el('div','group');
  const t = el('div','gtitle');
  t.appendChild(document.createTextNode(title));
  if(tag) t.appendChild(el('span','gtag', tag));
  g.appendChild(t);

  const row = el('div','btnrow');
  row.appendChild(copyBtn('复制上线命令', title, 'btn-primary', () => cmds.on(m.key)));
  row.appendChild(copyBtn('复制下线命令', title, '', () => cmds.off(m.key)));
  row.appendChild(copyBtn('复制卸载命令', title, 'btn-ghost btn-danger', () => cmds.uninstall(m.key)));
  const v = el('button','btn btn-ghost','查看命令');
  v.onclick = () => showManual(m.name + ' · ' + title, manualItems(m));
  row.appendChild(v);
  g.appendChild(row);
  return g;
}

function renderMachines(){
  const box = document.getElementById('machines');
  box.innerHTML = '';
  document.getElementById('mcount').textContent = MACHINES.length ? MACHINES.length + ' 台' : '暂无';
  if(!MACHINES.length){
    box.appendChild(el('div','empty','还没有机器，用下面的表单添加一台。'));
    return;
  }
  for(let idx = 0; idx < MACHINES.length; idx++){
    const m = MACHINES[idx];
    const card = el('div','mcard');

    const head = el('div','mhead');
    head.appendChild(el('div','mname', m.name));
    const pill = el('span','pill ' + (m.online ? 'on' : 'off'));
    pill.dataset.idx = String(idx);
    pill.appendChild(el('span','dot'));
    pill.appendChild(el('span','pill-text', m.online ? '在线' : '离线'));
    head.appendChild(pill);
    card.appendChild(head);

    const meta = el('div','mmeta');
    const c1 = el('span','chip'); c1.appendChild(document.createTextNode('映射端口 '));
    c1.appendChild(el('b', null, String(m.port))); meta.appendChild(c1);
    meta.appendChild(el('span','arrow','←'));
    const c2 = el('span','chip'); c2.appendChild(document.createTextNode('本机 '));
    c2.appendChild(el('b', null, String(m.net_port))); meta.appendChild(c2);
    card.appendChild(meta);

    card.appendChild(osGroup('Linux / macOS', '需要 sudo', CMDS_UNIX, m,
      mm => ([
        {label:'上线命令（装 sshd + 起隧道）', text: CMD_SH(mm.key)},
        {label:'下线命令（只停隧道，保留客户端文件与 sshd）', text: CMD_STOP_SH(mm.key)},
        {label:'卸载命令（停隧道 + 删除客户端文件，不动 sshd）', text: CMD_UNINSTALL_SH(mm.key)},
      ])));
    card.appendChild(osGroup('Windows', '需管理员 PowerShell', CMDS_WIN, m,
      mm => ([
        {label:'上线命令（装 OpenSSH Server + 起隧道）', text: CMD_PS(mm.key)},
        {label:'下线命令（只停隧道，保留客户端文件与 sshd）', text: CMD_STOP_PS(mm.key)},
        {label:'卸载命令（停隧道 + 删除客户端文件，不动 sshd）', text: CMD_UNINSTALL_PS(mm.key)},
      ])));

    const foot = el('div','mfoot');
    const del = el('button','btn btn-ghost btn-danger','删除这台机器');
    del.onclick = () => delMachine(m.name);
    foot.appendChild(del);
    card.appendChild(foot);

    box.appendChild(card);
  }
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
  if(!confirm('删除机器 ' + name + '？它的上线/下线命令会立即失效。')) return;
  if(await api('/api/machines/delete', {name})){ toast('已删除'); setTimeout(()=>location.reload(), 700); }
}

function statusSelector(idx){
  return '[data-idx="' + idx + '"]';
}
async function refreshStatus(){
  try{
    const r = await fetch('/api/status');
    const j = await r.json();
    MACHINES.forEach((m, idx) => {
      const online = !!(j.machines || {})[m.name];
      m.online = online;
      const pill = document.querySelector(statusSelector(idx));
      if(pill){
        pill.className = 'pill ' + (online ? 'on' : 'off');
        const t = pill.querySelector('.pill-text');
        if(t) t.textContent = online ? '在线' : '离线';
      }
    });
  }catch(e){}
}

renderMachines();
setInterval(refreshStatus, 5000);
refreshStatus();
</script>
</body>
</html>
"""


def machines_payload(cfg):
    """给前端的机器数据：卡片在前端渲染，避免把用户输入拼进 HTML/JS 里"""
    payload = []
    for m in cfg["machines"]:
        payload.append({
            "name": str(m["name"]),
            "key": str(m["key"]),
            "port": int(m["port"]),
            "net_port": int(m.get("net_port", 22)),
            "online": port_is_open(m["port"]),
        })
    return json.dumps(payload, ensure_ascii=False)


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
        cfg = current_config()
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
            return self.send_json(200, public_config(current_config()))
        if path == "/api/status":
            if not self.require_auth():
                return
            return self.send_json(200, {"machines": {
                m["name"]: port_is_open(m["port"]) for m in current_config()["machines"]}})
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
                publish_config(cfg)
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
                publish_config(cfg)
            return self.send_json(200, {"ok": True, "port": port})

        if path == "/api/machines/delete":
            name = str(body.get("name", "")).strip()
            with _config_lock:
                cfg = load_config()
                before = len(cfg["machines"])
                cfg["machines"] = [m for m in cfg["machines"] if m["name"] != name]
                if len(cfg["machines"]) == before:
                    return self.send_json(404, {"ok": False, "error": "机器不存在"})
                publish_config(cfg)
            return self.send_json(200, {"ok": True})

        return self.send_text(404, "not found")

    # ---------- 具体处理 ----------
    def serve_page(self):
        cfg = current_config()

        warn = ""
        if not cfg.get("token"):
            warn = ('<div class="card warn">还没设置 token：脚本会拿空 token 去认证，服务端会拒绝。'
                    '请填入与服务端 <code>-token</code> 一致的值。</div>')

        replacements = {
            "<!--MACHINES-->": machines_payload(cfg),
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
        cfg = current_config()
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

        # /i/<key>/stop.sh | .ps1      —— 只停隧道
        if rest and rest[0].startswith("stop"):
            if rest[0].endswith(".ps1") or ps1:
                return self.send_text(200, render("stop.ps1.tmpl", machine_mapping(cfg, machine)),
                                      "text/plain; charset=utf-8")
            return self.send_text(200, render("stop.sh.tmpl", machine_mapping(cfg, machine)),
                                  "text/plain; charset=utf-8")

        # /i/<key>/uninstall.sh | .ps1 —— 停隧道 + 删文件（不动 sshd）
        if rest and rest[0].startswith("uninstall"):
            if rest[0].endswith(".ps1") or ps1:
                return self.send_text(200, render("uninstall.ps1.tmpl", machine_mapping(cfg, machine)),
                                      "text/plain; charset=utf-8")
            return self.send_text(200, render("uninstall.sh.tmpl", machine_mapping(cfg, machine)),
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
    try:
        _config_mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        _config_mtime = 0.0
    host, _, port = args.listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    print("OpNet 面板已启动: http://%s:%s  (配置: %s)" % (host, port, CONFIG_PATH), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

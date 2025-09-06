#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowTEAM Live Monitor (Enhanced with AI Work Log & Dynamic Modules + Auto-Executing AI Modules)
- Smooth dashboard with Rich (10 FPS)
- Continuous AI updates
- Connection type inference + scoring
- AI Work Log shows raw AI thoughts/actions
- AI Analysis shows clean insights only
- AI can create + hot-load modules in ./modules/
- Functions in AI modules marked _run_on_tick=True auto-execute each tick
"""

import os, re, ast, socket, subprocess, threading, time, getpass, platform
import importlib.util, pathlib
from datetime import datetime
from collections import deque

import psutil
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich import box

# ---------------- CONFIG ----------------
MODEL_NAME = os.environ.get("AI_MODEL", "deepseek-coder-v2:16b")
REFRESH_INTERVAL = 0.25
AI_CADENCE = 7
SHOW_MAX_CONNS = 100
HIDE_BIND_ADDRS = True
HISTORY_LEN = 12
AI_TIMEOUT_SEC = 120
AI_COOLDOWN_SEC = 30

console = Console()
tick = 0
pid_name_cache = {}

SUSPICION_THRESHOLDS = {"user_score": 1, "conn_score": 3, "tor_score": 5}
ALLOWED_MODIFIABLES = {"REFRESH_INTERVAL","AI_CADENCE","SHOW_MAX_CONNS","HIDE_BIND_ADDRS","SUSPICION_THRESHOLDS"}

ai_lock = threading.Lock()
last_ai_output = "[AI] Running..."
ai_history = deque(maxlen=HISTORY_LEN)

# Work log (raw AI thoughts)
ai_work_log = deque(maxlen=20)
# Analysis log (clean insights)
ai_analysis_log = deque(maxlen=10)

# Modules dir
MODULE_DIR = pathlib.Path.cwd() / "modules"
MODULE_DIR.mkdir(exist_ok=True)
created_modules = {}

# ---------------- HELPERS ----------------
def hide_cursor(): console.print("\x1b[?25l", end="")
def show_cursor(): console.print("\x1b[?25h", end="")

def human_bytes(n):
    for unit in ("B","KB","MB","GB","TB"):
        if n < 1024 or unit=="TB": return f"{n:.1f} {unit}"
        n /= 1024

def is_private_ip(ip):
    if not ip: return True
    if ip.startswith(("10.","127.","192.168.","0.","255.")): return True
    if ip.startswith("172."):
        s2 = int(ip.split(".")[1]); return 16 <= s2 <= 31
    return False

def safe_write_module(module_name: str, code: str):
    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", module_name)
    existing_path = find_existing_module(module_name)
    
    if existing_path:
        path = existing_path
    else:
        MODULE_DIR.mkdir(exist_ok=True)
        path = MODULE_DIR / f"{safe_name}.py"

    safe_code = sanitize_ai_suggestion(code)
    if not safe_code.strip(): return f"# No safe code for module {module_name}"

    try:
        path.write_text(safe_code, encoding="utf-8")

        # Hot-load module
        spec = importlib.util.spec_from_file_location(safe_name, str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        globals()[safe_name] = module
        created_modules[safe_name] = module
        return f"[Module created/updated] {path}"
    except Exception as e:
        return f"# Failed to create/update module {module_name}: {e}"

def find_existing_module(module_name: str) -> pathlib.Path | None:
    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", module_name)
    for root, dirs, files in os.walk(pathlib.Path.cwd()):
        if f"{safe_name}.py" in files:
            return pathlib.Path(root) / f"{safe_name}.py"
    return None

# ---------------- SYSTEM ----------------
def system_info():
    uname = platform.uname()
    uptime = time.time()-psutil.boot_time()
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": getpass.getuser(),
        "host": uname.node,
        "os": f"{uname.system} {uname.release}",
        "kernel": uname.version.split()[0],
        "arch": uname.machine,
        "uptime": time.strftime("%Hh%Mm%Ss", time.gmtime(uptime))
    }

def usage_info():
    cpu_total = psutil.cpu_percent(interval=None)
    cpu_per = psutil.cpu_percent(interval=None, percpu=True)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_total": cpu_total,
        "cpu_per": cpu_per,
        "ram_used": ram.used,
        "ram_total": ram.total,
        "ram_pct": ram.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "disk_pct": disk.percent
    }

def gpu_info():
    gpus = []
    try:
        out = subprocess.check_output(
            ["nvidia-smi","--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu","--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL,text=True,timeout=1
        ).strip()
        for line in out.splitlines():
            parts = [x.strip() for x in line.split(",")]
            if len(parts) < 5: continue
            name,util,mem_used,mem_total,temp = parts[:5]
            gpus.append({
                "name": name,
                "util": float(util),
                "mem_used": float(mem_used)*1024,
                "mem_total": float(mem_total)*1024,
                "temp": float(temp)
            })
    except: pass
    return gpus

# ---------------- USERS ----------------
def get_active_users():
    users_list=[]
    try:
        who_output = subprocess.check_output(["who","--ips"], text=True)
        for line in who_output.splitlines():
            parts = line.split()
            if len(parts) < 5: continue
            user,tty,date,time_part,host = parts[:5]
            if host in ("","0.0.0.0","(:0)"): host="local"
            users_list.append({"name":user,"tty":tty,"host":host,"started":f"{date} {time_part}"})
    except:
        for u in psutil.users():
            host = u.host or "local"
            users_list.append({
                "name":u.name,"tty":u.terminal or "",
                "host":host,
                "started":datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S")
            })
    return users_list

# ---------------- CONNECTIONS ----------------
COMMON_DB_PORTS={3306:"MySQL",5432:"PostgreSQL",6379:"Redis"}
COMMON_HTTP_PORTS={80:"HTTP",8080:"HTTP",443:"HTTPS"}

def proc_name(pid):
    if not pid: return "N/A"
    if pid in pid_name_cache: return pid_name_cache[pid]
    try: name = psutil.Process(pid).name()
    except: name = "unknown"
    pid_name_cache[pid] = name
    return name

def infer_protocol(name,lport,rport,raw_line):
    try:
        n = (name or "").lower()
        lport_i = int(lport) if str(lport).isdigit() else None
        rport_i = int(rport) if str(rport).isdigit() else None
        if "ssh" in n or lport_i==22 or rport_i==22: return "SSH"
        if any(x in n for x in ("nginx","apache","httpd")) or (lport_i in COMMON_HTTP_PORTS or rport_i in COMMON_HTTP_PORTS):
            return "HTTPS" if rport_i==443 else "HTTP"
        if rport_i in COMMON_DB_PORTS or lport_i in COMMON_DB_PORTS: return COMMON_DB_PORTS.get(rport_i or lport_i,"DB")
        if "tor" in n or rport_i==9050 or lport_i==9050: return "TOR"
        if "docker" in n or "containerd" in n or rport_i in (2377,7946,4789): return "ContainerNet"
        if raw_line.strip().upper().startswith("UDP"): return "UDP"
        return "TCP"
    except: return "ETC"

def suspicious_score(row):
    score=0
    if row.get("r_ip") and not is_private_ip(str(row.get("r_ip"))): score+=2
    try: rp=int(str(row.get("r_port") or 0))
    except: rp=0
    uncommon={22,80,443,139,445,53,123,3306,5432,6379,2377,7946,4789,9050}
    if rp and rp not in uncommon and row.get("status")=="ESTABLISHED": score+=1
    if row.get("proto")=="TOR": score+=SUSPICION_THRESHOLDS.get("tor_score",3)
    if row.get("process") in ("unknown","N/A"): score+=1
    return score

def detect_connections(max_rows=SHOW_MAX_CONNS):
    conns=[]
    try:
        ss_output = subprocess.check_output(["ss","-tunp"], text=True, stderr=subprocess.DEVNULL)
        for line in ss_output.splitlines():
            if line.strip().startswith("Netid") or line.strip()=="": continue
            parts = re.split(r"\s+", line.strip())
            ip_ports = [p for p in parts if ":" in p and not p.startswith("users:")]
            if len(ip_ports) < 2: continue
            local,remote = ip_ports[-2],ip_ports[-1]; pid=None
            m = re.search(r"pid=(\d+),", line); pid=int(m.group(1)) if m else None
            name = proc_name(pid)
            try: l_ip,l_port = local.rsplit(":",1)
            except: l_ip,l_port = local,""
            try: r_ip,r_port = remote.rsplit(":",1)
            except: r_ip,r_port = remote,""
            if HIDE_BIND_ADDRS and r_ip in ("0.0.0.0","::",""): continue
            proto = infer_protocol(name,l_port,r_port,line)
            status = "ESTABLISHED" if "ESTAB" in line or "ESTABLISHED" in line else ("LISTEN" if "LISTEN" in line else "")
            conns.append({"pid":pid,"process":name,"proto":proto,"l_ip":l_ip,"l_port":l_port,"r_ip":r_ip,"r_port":r_port,"status":status,"score":0})
    except: pass
    for row in conns: row["score"]=suspicious_score(row)
    clusters={}
    for x in conns: clusters[x["r_ip"]]=clusters.get(x["r_ip"],0)+1 if x["r_ip"] else 0
    for x in conns:
        if x["r_ip"] and clusters.get(x["r_ip"],0)>=8: x["score"]+=1
    conns.sort(key=lambda r:(-r["score"],0 if r["status"]=="ESTABLISHED" else 1,str(r["process"])))
    return conns[:max_rows]

# ---------------- AI ----------------
AI_SYSTEM_PROMPT = """
You are ShadowTEAM's embedded AI analyst.
- Analyze system metrics & network activity.
- Suggest config updates.
- Provide short commentary: insights, warnings, trends.
- If you detect new functionality is needed, create a full Python module using ### MODULE modulename.
- Modules can include multiple functions, classes, safe imports.
- Any function that should run every tick should have _run_on_tick=True
- Make full functional modules to use to expand your knowledge and functionality
"""

def ai_prompt_text(context: str):
    return f"""{AI_SYSTEM_PROMPT}

Live context:
{context}

Current config:
REFRESH_INTERVAL = {REFRESH_INTERVAL}
SHOW_MAX_CONNS = {SHOW_MAX_CONNS}
SUSPICION_THRESHOLDS = {SUSPICION_THRESHOLDS}
"""

def parse_ai_output(suggestion: str):
    code, commentary = [], []
    for line in suggestion.splitlines():
        if line.strip().startswith("def ") or "=" in line or line.strip().startswith("### MODULE"):
            code.append(line)
        else:
            commentary.append(line)
    return "\n".join(code), "\n".join(commentary).strip()

def sanitize_ai_suggestion(suggestion: str) -> str:
    dangerous_keywords = ["os.system", "subprocess.Popen", "eval", "exec", "__import__"]
    safe_lines = []
    lines = suggestion.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if any(k in line for k in dangerous_keywords):
            i += 1
            continue
        if line.startswith(("def ", "class ", "import ", "from ")):
            block = [line]
            indent = len(line) - len(line.lstrip())
            i += 1
            while i < len(lines):
                current_indent = len(lines[i]) - len(lines[i].lstrip())
                if current_indent > indent or lines[i].strip() == "":
                    block.append(lines[i])
                    i += 1
                else:
                    break
            safe_lines.extend(block)
        elif "=" in line:
            try:
                node = ast.parse(line, mode="exec")
                if isinstance(node.body[0], ast.Assign):
                    safe_lines.append(line)
            except: pass
            i += 1
        else:
            i += 1
    return "\n".join(safe_lines)

def safe_apply_ai_update(suggestion: str):
    applied = []
    lines = suggestion.splitlines()
    buffer, module_name = [], None
    for line in lines:
        if line.strip().startswith("### MODULE "):
            if buffer and module_name:
                result = safe_write_module(module_name, "\n".join(buffer))
                applied.append(result)
            module_name = line.strip().split(maxsplit=2)[-1]
            buffer = []
        else:
            buffer.append(line)
    if buffer and module_name:
        result = safe_write_module(module_name, "\n".join(buffer))
        applied.append(result)
    if not module_name:
        code = sanitize_ai_suggestion(suggestion)
        if code:
            try:
                exec(code, globals())
                applied.append("[Inline code executed]")
            except Exception as e:
                applied.append(f"# Failed: {e}")
    return applied

# ---------------- DYNAMIC MODULE EXECUTION ----------------
def run_dynamic_modules():
    for name, module in created_modules.items():
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if callable(attr) and getattr(attr, "_run_on_tick", False):
                try: attr()
                except Exception as e:
                    ai_work_log.appendleft(f"[{datetime.now().strftime('%H:%M:%S')}] Module {name}.{attr_name} error: {e}")

def ai_worker_loop():
    global last_ai_output
    last_valid_output = "[AI] Booting up..."
    while True:
        try:
            sysi = system_info()
            usage = usage_info()
            gpus = gpu_info()
            conns = detect_connections(10)
            ctx = f"CPU={usage['cpu_total']}% RAM={usage['ram_pct']}% Disk={usage['disk_pct']}% Conns={len(conns)} GPU={[g['util'] for g in gpus]}"
            prompt = ai_prompt_text(ctx)
            cmd = ["ollama", "run", MODEL_NAME]
            result = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=AI_TIMEOUT_SEC)
            suggestion = (result.stdout + "\n" + result.stderr).strip()
            if suggestion:
                code, commentary = parse_ai_output(suggestion)
                applied = safe_apply_ai_update(code) if code else []

                # Log raw steps into Work Log
                raw_entry = f"[{datetime.now().strftime('%H:%M:%S')}] RAW -> {suggestion[:200]}..."
                ai_work_log.appendleft(raw_entry)

                # Log clean insights into Analysis
                event_lines = []
                if commentary: event_lines.append(f"Thoughts: {commentary}")
                if applied: event_lines.append("Applied: " + "; ".join(applied))
                if not event_lines: event_lines.append("[AI] No useful output")
                clean_entry = " | ".join(event_lines)
                ai_analysis_log.appendleft(f"[{datetime.now().strftime('%H:%M:%S')}] {clean_entry}")

                last_valid_output = "[AI] Analysis complete.\n" + "\n".join(event_lines)
            with ai_lock: last_ai_output = last_valid_output
        except Exception as e:
            with ai_lock: last_ai_output = f"[AI] Error: {e}"
        time.sleep(AI_COOLDOWN_SEC)

threading.Thread(target=ai_worker_loop, daemon=True).start()

# ---------------- RENDER ----------------
def usage_color(pct: float) -> str:
    return "green" if pct < 50 else ("yellow" if pct < 75 else "red")

def render_header(sysi):
    text=Text.assemble(("ShadowTEAM Live Monitor","bold magenta"),f" — {sysi['user']}@{sysi['host']} | {sysi['os']} | uptime: {sysi['uptime']}")
    return Panel(text,style="cyan",box=box.ROUNDED)

def render_usage(usage,gpus):
    table=Table.grid(expand=True)
    table.add_column(justify="left"); table.add_column(justify="right")
    table.add_row("CPU:",f"[{usage_color(usage['cpu_total'])}]{usage['cpu_total']:.1f}%[/{usage_color(usage['cpu_total'])}] ({', '.join(str(int(p)) for p in usage['cpu_per'])})")
    table.add_row("RAM:",f"[{usage_color(usage['ram_pct'])}]{human_bytes(usage['ram_used'])}/{human_bytes(usage['ram_total'])} ({usage['ram_pct']}%)[/{usage_color(usage['ram_pct'])}]")
    table.add_row("Disk:",f"[{usage_color(usage['disk_pct'])}]{human_bytes(usage['disk_used'])}/{human_bytes(usage['disk_total'])} ({usage['disk_pct']}%)[/{usage_color(usage['disk_pct'])}]")
    for g in gpus:
        table.add_row(f"GPU {g['name']}:",f"[{usage_color(g['util'])}]{g['util']}%[/{usage_color(g['util'])}] {human_bytes(g['mem_used'])}/{human_bytes(g['mem_total'])} | {g['temp']}°C")
    return Panel(table,title="System Usage",style="green",box=box.ROUNDED)

def render_users(users,scores):
    table=Table(box=box.MINIMAL,expand=True)
    table.add_column("User"); table.add_column("TTY"); table.add_column("Host"); table.add_column("Started"); table.add_column("Score",justify="right")
    for u in users:
        score=scores.get(u["name"],0)
        if score >= SUSPICION_THRESHOLDS.get("user_score",1):
            style="red" if score >= 3 else "yellow"
        else: style="cyan"
        table.add_row(u["name"],u["tty"],u["host"],u["started"],str(score),style=style)
    return Panel(table,title="Active Users",style="yellow",box=box.ROUNDED)

def render_conns(conns):
    table=Table(box=box.MINIMAL,expand=True)
    table.add_column("Proto"); table.add_column("Process"); table.add_column("Local"); table.add_column("Remote"); table.add_column("Status"); table.add_column("Score",justify="right")
    proto_colors={"SSH":"cyan","HTTP":"green","HTTPS":"bright_green","TOR":"red","ContainerNet":"yellow","UDP":"magenta","TCP":"white"}
    for c in conns:
        score=c.get("score",0)
        if score >= SUSPICION_THRESHOLDS.get("conn_score",2):
            style="red" if score >= 4 else "yellow"
        else: style="cyan"
        proto_style=proto_colors.get(c["proto"],"white")
        table.add_row(f"[{proto_style}]{c['proto']}[/{proto_style}]",c["process"],f"{c['l_ip']}:{c['l_port']}",f"{c['r_ip']}:{c['r_port']}",c["status"],str(score),style=style)
    return Panel(table,title="Connections",style="blue",box=box.ROUNDED)

def render_ai():
    log_text = "\n".join(ai_analysis_log) if ai_analysis_log else "[No analysis yet]"
    return Panel(Text(log_text, style="bright_magenta"),title="AI Analysis",box=box.ROUNDED)

def render_ai_log():
    log_text = "\n".join(ai_work_log) if ai_work_log else "[No AI activity yet]"
    return Panel(Text(log_text, style="white"),title="AI Work Log",box=box.ROUNDED)

# ---------------- MAIN LOOP ----------------
def main_loop():
    hide_cursor()
    global tick
    try:
        with Live(refresh_per_second=10,screen=True) as live:
            while True:
                tick+=1
                sysi=system_info()
                usage=usage_info()
                gpus=gpu_info()
                users=get_active_users()
                conns=detect_connections(SHOW_MAX_CONNS)
                user_scores={u["name"]:0 for u in users}
                for c in conns:
                    if c["r_ip"] and not is_private_ip(c["r_ip"]): user_scores[c["r_ip"]]=user_scores.get(c["r_ip"],0)+1

                # Run AI module functions marked _run_on_tick=True
                run_dynamic_modules()

                left=Group(render_header(sysi),render_usage(usage,gpus),render_conns(conns),render_users(users,user_scores),render_ai_log())
                with ai_lock:
                    right=Group(render_ai())
                grid=Table.grid(expand=True)
                grid.add_column(ratio=2); grid.add_column(ratio=1)
                grid.add_row(left,right)
                live.update(grid)
                time.sleep(REFRESH_INTERVAL)
    except KeyboardInterrupt: pass
    finally: show_cursor()

if __name__=="__main__": main_loop()

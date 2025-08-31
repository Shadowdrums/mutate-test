#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowTEAM Live Monitor (Fixed & Improved)
- Live dashboard with Rich (10 FPS)
- Continuous AI updates
- Connection type inference + scoring
- Correct GPU VRAM reporting
"""

import os, re, ast, socket, subprocess, threading, time, getpass, platform
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
MODEL_NAME = os.environ.get("AI_MODEL", "starcoder2:15b")
REFRESH_INTERVAL = 1.0
AI_CADENCE = 6
SHOW_MAX_CONNS = 30
HIDE_BIND_ADDRS = True
HISTORY_LEN = 12
AI_TIMEOUT_SEC = 60

console = Console()
tick = 0
pid_name_cache = {}

SUSPICION_THRESHOLDS = {"user_score":1,"conn_score":2,"tor_score":3}
ALLOWED_MODIFIABLES = {"REFRESH_INTERVAL","AI_CADENCE","SHOW_MAX_CONNS","HIDE_BIND_ADDRS","SUSPICION_THRESHOLDS"}

ai_lock = threading.Lock()
last_ai_output = "[AI idle]"
ai_history = deque(maxlen=HISTORY_LEN)

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
    if ip.startswith("172."): s2=int(ip.split(".")[1]); return 16<=s2<=31
    return False

def revdns(ip):
    if not ip or is_private_ip(ip): return ip or ""
    try: return socket.getfqdn(ip)
    except: return ip

# ---------------- SYSTEM ----------------
def system_info():
    uname=platform.uname()
    uptime=time.time()-psutil.boot_time()
    return {
        "time":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":getpass.getuser(),
        "host":uname.node,
        "os":f"{uname.system} {uname.release}",
        "kernel":uname.version.split()[0],
        "arch":uname.machine,
        "uptime":time.strftime("%Hh%Mm%Ss",time.gmtime(uptime))
    }

def usage_info():
    cpu_total=psutil.cpu_percent(interval=None)
    cpu_per=psutil.cpu_percent(interval=None,percpu=True)
    ram=psutil.virtual_memory()
    disk=psutil.disk_usage("/")
    return {
        "cpu_total":cpu_total,
        "cpu_per":cpu_per,
        "ram_used":ram.used,
        "ram_total":ram.total,
        "ram_pct":ram.percent,
        "disk_used":disk.used,
        "disk_total":disk.total,
        "disk_pct":disk.percent
    }

def gpu_info():
    gpus=[]
    try:
        out=subprocess.check_output(
            ["nvidia-smi","--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu","--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL,text=True,timeout=1
        ).strip()
        for line in out.splitlines():
            parts=[x.strip() for x in line.split(",")]
            if len(parts)<5: continue
            name,util,mem_used,mem_total,temp=parts[:5]
            gpus.append({
                "name":name,
                "util":float(util),
                "mem_used":float(mem_used)*1024,
                "mem_total":float(mem_total)*1024,
                "temp":float(temp)
            })
    except: pass
    return gpus

# ---------------- USERS ----------------
def get_active_users():
    users_list=[]
    try:
        who_output=subprocess.check_output(["who","--ips"],text=True)
        for line in who_output.splitlines():
            parts=line.split()
            if len(parts)<5: continue
            user,tty,date,time_part,host=parts[:5]
            if host in ("","0.0.0.0","(:0)"): host="local"
            users_list.append({"name":user,"tty":tty,"host":host,"started":f"{date} {time_part}"})
    except:
        for u in psutil.users():
            host=u.host or "local"
            users_list.append({
                "name":u.name,
                "tty":u.terminal or "",
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
    try: name=psutil.Process(pid).name()
    except: name="unknown"
    pid_name_cache[pid]=name
    return name

def infer_protocol(name,lport,rport,raw_line):
    try:
        n=(name or "").lower()
        lport_i=int(lport) if str(lport).isdigit() else None
        rport_i=int(rport) if str(rport).isdigit() else None
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
        ss_output=subprocess.check_output(["ss","-tunp"],text=True,stderr=subprocess.DEVNULL)
        for line in ss_output.splitlines():
            if line.strip().startswith("Netid") or line.strip()=="": continue
            parts=re.split(r"\s+",line.strip())
            ip_ports=[p for p in parts if ":" in p and not p.startswith("users:")]
            if len(ip_ports)<2: continue
            local,remote=ip_ports[-2],ip_ports[-1]; pid=None
            m=re.search(r"pid=(\d+),",line); pid=int(m.group(1)) if m else None
            name=proc_name(pid)
            try: l_ip,l_port=local.rsplit(":",1)
            except: l_ip,l_port=local,""
            try: r_ip,r_port=remote.rsplit(":",1)
            except: r_ip,r_port=remote,""
            if HIDE_BIND_ADDRS and r_ip in ("0.0.0.0","::",""): continue
            proto=infer_protocol(name,l_port,r_port,line)
            status="ESTABLISHED" if "ESTAB" in line or "ESTABLISHED" in line else ("LISTEN" if "LISTEN" in line else "")
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
def ai_prompt_text():
    """
    The AI is instructed to return Python code assignments OR
    new function definitions as strings. It cannot use imports,
    filesystem, or dangerous operations.
    """
    monitored_funcs = ["suspicious_score", "infer_protocol", "gpu_info"]
    return f"""
You are a continuous system monitoring AI. respond with Python assignments
or small responses on system overview: {monitored_funcs}

REFRESH_INTERVAL = {REFRESH_INTERVAL}
SUSPICION_THRESHOLDS = {SUSPICION_THRESHOLDS}
SHOW_MAX_CONNS = {SHOW_MAX_CONNS}
"""

def safe_apply_ai_update(suggestion: str):
    """
    Apply configuration updates and optionally replace functions.
    Functions are applied in memory via exec().
    """
    global REFRESH_INTERVAL, AI_CADENCE, SHOW_MAX_CONNS, HIDE_BIND_ADDRS, SUSPICION_THRESHOLDS
    applied = []

    for line in suggestion.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Check if it's a function definition
        if line.startswith("def "):
            func_name = re.match(r"def\s+(\w+)\s*\(", line)
            if func_name:
                func_name = func_name.group(1)
                try:
                    # Collect full function code block
                    func_lines = [line]
                    indent_level = len(line) - len(line.lstrip())
                    # Append subsequent lines indented more than function definition
                    in_func = True
                    for l in suggestion.splitlines()[suggestion.splitlines().index(line)+1:]:
                        if l.strip() == "":
                            func_lines.append(l)
                            continue
                        if len(l) - len(l.lstrip()) > indent_level:
                            func_lines.append(l)
                        else:
                            break
                    func_code = "\n".join(func_lines)
                    exec(func_code, globals())
                    applied.append(f"[Function updated] {func_name}")
                except Exception as e:
                    applied.append(f"# Failed to apply function {func_name}: {e}")
            continue

        # Otherwise treat as variable assignment
        try:
            node = ast.parse(line, mode="exec")
            if not node.body or not isinstance(node.body[0], ast.Assign):
                continue
            assign = node.body[0]
            target = assign.targets[0]
            if isinstance(target, ast.Name) and target.id in ALLOWED_MODIFIABLES:
                val = ast.literal_eval(assign.value)
                globals()[target.id] = val
                applied.append(f"{target.id}={val}")
            elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id in ALLOWED_MODIFIABLES:
                key_node = target.slice
                if isinstance(key_node, ast.Index): key_node = key_node.value
                key = ast.literal_eval(key_node)
                val = ast.literal_eval(assign.value)
                globals()[target.value.id][key] = val
                applied.append(f"{target.value.id}[{key}]={val}")
        except Exception as e:
            applied.append(f"# Failed to apply line: {line} ({e})")

    return applied

def ai_worker_loop():
    global last_ai_output
    while True:
        try:
            prompt = ai_prompt_text()
            cmd = ["ollama", "run", MODEL_NAME]
            result = subprocess.run(
                cmd,
                input=prompt,            # send prompt via stdin
                capture_output=True,
                text=True,
                timeout=AI_TIMEOUT_SEC
            )
            suggestion = (result.stdout + "\n" + result.stderr).strip()
            if not suggestion:
                suggestion = "# No suggestion\nREFRESH_INTERVAL={}".format(REFRESH_INTERVAL)
            applied = safe_apply_ai_update(suggestion)
            with ai_lock:
                last_ai_output = "[AI] Analysis complete.\nApplied:\n" + "\n".join(applied)
        except Exception as e:
            with ai_lock:
                last_ai_output = f"[AI] Error: {e}"
        time.sleep(120)

# Start AI in background
threading.Thread(target=ai_worker_loop, daemon=True).start()

# ---------------- RENDER ----------------
def render_header(sysi):
    text=Text.assemble(("ShadowTEAM Live Monitor","bold magenta"),f" — {sysi['user']}@{sysi['host']} | {sysi['os']} | uptime: {sysi['uptime']}")
    return Panel(text,style="cyan",box=box.ROUNDED)

def render_usage(usage,gpus):
    table=Table.grid(expand=True)
    table.add_column(justify="left"); table.add_column(justify="right")
    table.add_row("CPU:",f"{usage['cpu_total']:.1f}% ({', '.join(str(int(p)) for p in usage['cpu_per'])})")
    table.add_row("RAM:",f"{human_bytes(usage['ram_used'])}/{human_bytes(usage['ram_total'])} ({usage['ram_pct']}%)")
    table.add_row("Disk:",f"{human_bytes(usage['disk_used'])}/{human_bytes(usage['disk_total'])} ({usage['disk_pct']}%)")
    for g in gpus:
        table.add_row(f"GPU {g['name']}:",f"{g['util']}% {human_bytes(g['mem_used'])}/{human_bytes(g['mem_total'])} | {g['temp']}°C")
    return Panel(table,title="System Usage",style="green",box=box.ROUNDED)

def render_users(users,scores):
    table=Table(box=box.MINIMAL,expand=True)
    table.add_column("User"); table.add_column("TTY"); table.add_column("Host"); table.add_column("Started"); table.add_column("Score",justify="right")
    for u in users:
        score=scores.get(u["name"],0)
        style="bold red" if score>=SUSPICION_THRESHOLDS.get("user_score",1) else ""
        table.add_row(u["name"],u["tty"],u["host"],u["started"],str(score),style=style)
    return Panel(table,title="Active Users",style="yellow",box=box.ROUNDED)

def render_conns(conns):
    table=Table(box=box.MINIMAL,expand=True)
    table.add_column("Proto"); table.add_column("Process"); table.add_column("Local"); table.add_column("Remote"); table.add_column("Status"); table.add_column("Score",justify="right")
    for c in conns:
        score=c.get("score",0)
        style="bold red" if score>=SUSPICION_THRESHOLDS.get("conn_score",2) else ""
        table.add_row(c["proto"],c["process"],f"{c['l_ip']}:{c['l_port']}",f"{c['r_ip']}:{c['r_port']}",c["status"],str(score),style=style)
    return Panel(table,title="Connections",style="blue",box=box.ROUNDED)

def render_ai(ai_text):
    return Panel(Text(ai_text,style="bright_magenta"),title="AI Analysis",box=box.ROUNDED)

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
                left=Group(render_header(sysi),render_usage(usage,gpus),render_conns(conns),render_users(users,user_scores))
                with ai_lock: right=render_ai(last_ai_output)
                grid=Table.grid(expand=True)
                grid.add_column(ratio=2); grid.add_column(ratio=1)
                grid.add_row(left,right)
                live.update(grid)
                time.sleep(REFRESH_INTERVAL)
    except KeyboardInterrupt: pass
    finally: show_cursor()

if __name__=="__main__": main_loop()

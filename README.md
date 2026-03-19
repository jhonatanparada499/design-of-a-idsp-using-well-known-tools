# Design of a IDSP Using Well Known Tools
TASK: investigate exactly what caused the alerts to be generated in experiment 1. Was it a signature and regex, some contemt in the metadata of the trafic?  

Research documentation as part of CRSP CUNY.  

**Currently working:** How to print the timestamp stats of when I started replying traffic to compare with evebox. What does the number in the Dashboard alert panel mean.  

## Table of Contents
- Environment Setup
- Background Knowledge
- Challenges and Resolutions
- Snort and Suricata Rules
- Event Viewer and Alert Management Tool (Evebox)
- Current Standing

## Environment Setup
Enable libvirtd service
```
sudo systemctl start libvirtd.service
```

Open virt-manager Virtual Machinve manager
```
virt-manager
```

Using only one virtual machine running Debian/LXDE

## Background Knowledge
### Suricata (Version: 7.0.10)
- (Done) [Rule Management](https://docs.suricata.io/en/suricata-8.0.2/rule-management/suricata-update.html)
- (Done) [Quickstart guide](https://docs.suricata.io/en/suricata-8.0.2/quickstart.html#basic-setup)
- (Done) [Suricata Rules](https://docs.suricata.io/en/suricata-8.0.2/rules/intro.html)  
- (11.9. Rule Profiling) [Performance](https://docs.suricata.io/en/latest/performance/)

**Statistics Notes**
- Tools to plot graphs: [Monitoring with Zabbix](http://christophe.vandeplas.com/2013/11/suricata-monitoring-with-zabbix-or-other.html), [Suri-stats](https://github.com/regit/suri-stats)  

**Suricata Rules Notes**
1. What are sticky buffers? Placen the buffer names first, then placing keywords that apply to it(e.g. http.uri; content:"hello")   
2. I think I understand the rule matching process, the syntax goes by key-pairs (key:pair) separated by semicolons. If a key has no pair (e.x. "...;ip.src;..." or "...dns.query;..." or "...;http.method;...") look up next key-pair value which will provide the info needed for the pairless key (e.x "ip.src;dataset:badips" or "dns.query;dataset:dns-bl" or http.method;content:"GET")  
* a function can be passed like (dns.query;to_md5;dataset:dns-bl)  
```
For example, to match against a DNS black list called dns-bl:

dns.query; dataset:isset,dns-bl; # This can be helpful to understand rule matching
```

"Normalized buffers are: all HTTP-keywords, reassembled streams, TLS-, SSL-, SSH-, FTP- and dcerpc-buffers"
![normalized buffers](https://docs.suricata.io/en/suricata-8.0.2/_images/normalization1.png)

3. Transactional rules (=>) [source](https://docs.suricata.io/en/suricata-8.0.2/rules/intro.html#transactional-rules)  
```
alert http any any => 5.6.7.8 80 (    # Match only when uri is sent and server responds with 200 stat code
  msg:"matching both uri and status";
  sid: 1;
  http.uri; content: "/download";
  http.stat_code; content: "200";
)
```

**Signatures using Regular Expressions for String Matching**  
```
alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
```
content="uid=0|28|root|29" means match whether uid=0, or uid=28, ..., uid=29. This example uses the pipe operator in ReGex.

Configuration file
```
sudo vim /etc/suricata/suricata.yaml
```

Running Suricata
```
sudo systemctl restart suricata
```

#### Logs and Stats Directory

```
ls /var/log/suricata/
```

To see alerts:
```
sudo tail -f /var/log/suricata/fast.log
```

To see rules (fetched using suricata-update, size: 41M):
```
/var/lib/suricata/rules/suricata.rules
```

#### Fetching ET Open ruleset
"With teh tool suricata-update rules can be fetched to be provided for Suricata"
```
sudo suricata-update
```

To enable rules that are disabled by default, use /etc/suricata/enable.conf

### Malware-Traffic-Analysis.com
- [2026-01-31 - TRAFFIC ANALYSIS EXERCISE: LUMMA IN THE ROOM-AH](https://www.malware-traffic-analysis.net/2026/01/31/index.html)

## Challenges & Resolutions
The Rule trigger example from the Suricata's Quickstart guide was not working on Debian VM. Thanks to this [article](https://www.criticaldesign.net/post/how-to-setup-a-suricata-ips), I realized that the interface parameter was misconfigured. I fixed it by switching from 'eth0' to 'enp1s0'.

![Suricata.yaml](./images/NIC_config.png)

## Snort and Suricata Rules
[Proofpoint Emerging Threats Rules](https://rules.emergingthreats.net/)
'The "ET" indicates the rule came from the Emerging Threats (Proofpoint) project.'

![Proofpoint Emerging Threats Rules](./images/Proofpoint_Emerging_Threats_Rules.png)

## Event Viewer and Alert Management Tool
[Evebox](https://github.com/jasonish/evebox) is a "a web-based, open-source event viewer and alert management tool."
[Evectl](https://evebox.org/evectl) "is a tool to help easily manage Suricata and EveBox on Linux systems using containers with Docker or Podman.". That is why I spent two weeks learning about Docker.  

![Evectl](./images/Evectl_Setup.png)

Disabling ET INFO Spotify, which is a noisy alert.  
![Disable](./images/Disable_conf.png)

Evectl TUI  
![Evectl_CLI](./images/EveCtl_CLI.png)

### [Docker](https://docs.docker.com/get-started/docker-overview/)
Source: https://docs.docker.com/engine/install/ubuntu/

Evebox Docker container was configured using the tutorial: [From Zero to a Home IDS Dashboard: Suricata + EveBox (with live alerts, GeoIP & rule tuning)](https://medium.com/@oscar.yanez.feijoo/from-zero-to-a-home-ids-dashboard-suricata-evebox-with-live-alerts-geoip-rule-tuning-0046003148fc)

Make sure Docker is enabled. Then run.
```
docker start evebox
```

Then access the web interface using ```https://localhost:5636```

### Local
I installed .deb package for debian at [Debian/Ubuntu x86_64](https://evebox.org/#downloads)
Runnig with ```evebox server -D . --datastore sqlite --input /var/log/suricata/eve.json```

Evebox filter syntax: Lucene-based query syntax

Evebox config file: ```/etc/evebox/evebox.yaml```

Task: Investigate how rule signatures work and how they are triggered. (Done)

## Replaying Traffic
[Tcpreplay](https://tcpreplay.appneta.com/) "is a suite of free Open Source utilities for editing and replaying previously captured network traffic".  
**Notes:** A mistake I make when I used this command last semester was not using the flag --topspeed. Without it, the replays took longer because it replayed the traffic at the same pace as it was captured.

```bash
root@pw29:~# tcpreplay -i eth7 -tK --loop 5000 --unique-ip smallFlows.pcap
File Cache is enabled
Actual: 71305000 packets (46082655000 bytes) sent in 38.05 seconds.
Rated: 1194330011.6 Bps, 9554.64 Mbps, 1848020.72 pps
Flows: 6045000 flows, 156669.03 fps, 71215000 flow packets, 90000 non-flow
Statistics for network device: eth7
	Attempted packets:         71305000
	Successful packets:        71305000
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 0
	Retried packets (EAGAIN):  0
```

## Current Standing  
- Experimenting

## Experiments
### 2026-01-31-traffic-analysis-exercise

**True Positives:** 13  
**False Positives:** 7  
**False Negative:** 0  

**Precision:** 65%  
**Recall:** 100%  
**F1 Score:** 78%  

| # | Count | Signature | Src -> Dst | Class | Rationale |
|---|-------|-----------|-----------|-------|-----------|
| 1 | 4 | SURICATA STREAM ESTABLISHED packet out of window (app_proto:smb) | 10.1.21.2 → 10.1.21.58 | FP | SMB stream reassembly noise from the DC; TCP artifact, not a confirmed malicious indicator |
| 2 | 4 | SURICATA STREAM ESTABLISHED invalid ack (app_proto:smb) | 10.1.21.58 → 10.1.21.2 | FP | TCP stream anomaly on SMB to DC; benign reassembly artifact |
| 3 | 4 | SURICATA STREAM Packet with invalid ack (app_proto:smb) | 10.1.21.58 → 10.1.21.2 | FP | Same as above; TCP artifact on normal SMB domain traffic |
| 4 | 1 | ET JA3 Hash — Possible SoftEther Windows Client SSTP Traffic (sni:communicationfirewall-security.cc) | 10.1.21.58 → 104.21.9.36 | TP | Lumma Stealer uses the SoftEther JA3 fingerprint; .cc domain is confirmed C2 |
| 5 | 15 | ET MALWARE Observed Win32/Lumma Stealer Related Domain (whitepepper.su) in TLS SNI | 10.1.21.58 → 153.92.1.49 | TP | Direct Lumma Stealer C2 domain hit in TLS SNI; high-confidence match |
| 6 | 13 | ET JA3 Hash — Possible SoftEther Windows Client SSTP Traffic (sni:whitepepper.su) | 10.1.21.58 → 153.92.1.49 | TP | Lumma's characteristic JA3 fingerprint to confirmed C2 host |
| 7 | 1 | ET DROP Spamhaus DROP Listed Traffic Inbound group 10 | 80.97.160.24 → 10.1.21.58 | TP | Inbound from a Spamhaus DROP-listed IP to the infected host; corroborates active C2 |
| 8 | 2 | ET DNS Query for .cc TLD (rrname:communicationfirewall-security.cc) | 10.1.21.58 → 10.1.21.2 | TP | Infected host resolving a known Lumma C2 domain via .cc TLD |
| 9 | 1 | SURICATA STREAM ESTABLISHED packet out of window (app_proto:tls) | 10.1.21.58 → 153.92.1.49 | TP | Stream anomaly on confirmed C2 channel (153.92.1.49 = whitepepper.su); malicious context makes this TP |
| 10 | 10 | ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup (whitepepper.su) | 10.1.21.58 → 10.1.21.2 | TP | DNS lookup for confirmed Lumma C2 domain; direct signature match |
| 11 | 10 | ET DNS Query for .su TLD (Soviet Union) Often Malware Related (rrname:whitepepper.su) | 10.1.21.58 → 10.1.21.2 | TP | .su lookup confirmed malicious (whitepepper.su = Lumma C2) |
| 12 | 6 | ET INFO HTTP Request to .su TLD (Soviet Union) Often Malware Related (hostname:whitepepper.su) | 10.1.21.58 → 153.92.1.49 | TP | HTTP to confirmed Lumma C2 host; staging/fingerprinting phase |
| 13 | 1 | ET MALWARE Lumma Stealer Victim Fingerprinting Activity (hostname:whitepepper.su) | 10.1.21.58 → 153.92.1.49 | TP | The scenario's primary alert; Lumma performing victim fingerprinting — highest-confidence TP |
| 14 | 2 | ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup (whooptm.cyou) | 10.1.21.58 → 10.1.21.2 | TP | Second Lumma C2 domain resolved by infected host |
| 15 | 1 | ET MALWARE Observed Win32/Lumma Stealer Related Domain (whooptm.cyou) in TLS SNI | 10.1.21.58 → 62.72.32.156 | TP | TLS connection to second confirmed Lumma C2 domain |
| 16 | 1 | ET JA3 Hash — Possible SoftEther Windows Client SSTP Traffic (sni:whooptm.cyou) | 10.1.21.58 → 62.72.32.156 | TP | Lumma JA3 fingerprint on second C2 channel |
| 17 | 1 | SURICATA STREAM excessive retransmissions (app_proto:tls) | 104.21.46.67 → 10.1.21.58 | FP | 104.21.46.67 is a Cloudflare IP; retransmissions are TCP noise, no confirmed malicious association |
| 18 | 1 | SURICATA STREAM excessive retransmissions (app_proto:tls) | 10.1.21.58 → 104.17.25.14 | FP | 104.17.25.14 is also Cloudflare; TCP retransmission noise |
| 19 | 2 | ET JA3 Hash — Possible SoftEther Windows Client SSTP Traffic (sni:assets.adobedtm.com) | 10.1.21.58 → 184.29.31.84 | FP | Adobe DTM is a legitimate marketing tag manager CDN; JA3 match is coincidental |
| 20 | 1 | ET INFO Microsoft Connection Test (hostname:www.msftconnecttest.com) | 10.1.21.58 → 23.55.178.249 | FP | Normal Windows network connectivity probe; fully benign |


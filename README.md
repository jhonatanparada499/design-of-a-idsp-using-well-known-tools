# Design of a IDSP Using Well Known Tools
Research documentation as part of CRSP CUNY.  

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
### Suricata
(Done) [Quickstart guide](https://docs.suricata.io/en/suricata-8.0.2/quickstart.html#basic-setup)

(10. Making sense out of Alerts) [Rule Management](https://docs.suricata.io/en/suricata-8.0.2/rule-management/suricata-update.html)

Version: 7.0.10

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

## Rules
[Proofpoint Emerging Threats Rules](https://rules.emergingthreats.net/)
'The "ET" indicates the rule came from the Emerging Threats (Proofpoint) project.'

![Proofpoint Emerging Threats Rules](./images/Proofpoint_Emerging_Threats_Rules.png)

## Event Viewer and Alert Management Tool
(Evebox)[https://github.com/jasonish/evebox] is a "a web-based, open-source event viewer and alert management tool."

### Docker ([Build, tag, and publish an image/Tagging images](https://docs.docker.com/get-started/docker-overview/))
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

Task: Investigate how rule signatures work and how they are triggered.

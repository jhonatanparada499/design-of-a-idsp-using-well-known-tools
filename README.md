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

## Suricata
[Quickstart guide](https://docs.suricata.io/en/suricata-8.0.2/quickstart.html#basic-setup)
Configuration file
```
sudo vim /etc/suricata/suricata.yaml
```

Running Suricata
```
sudo systemctl restart suricata
```

### Logs and Stats Directory

```
ls /var/log/suricata/
```



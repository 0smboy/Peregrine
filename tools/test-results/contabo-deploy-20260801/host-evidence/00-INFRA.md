# Contabo infra gate 2026-08-01T12:58:24Z

| node | public | proxy | storage | repl | VIP | mounts | selinux | keepalived |
|---|---|---|---|---|---|---|---|---|
| swift1 | 169.58.108.85 | 10.0.0.1 | 10.0.4.1 | 10.0.8.1 | yes | 3/3 | Enforcing | active |
### swift1
```
SEL=Enforcing
KA=active
VIP=1
M=111

/dev/sda5        50G  389M   50G   1% /srv/node/d1
/dev/sda6        50G  389M   50G   1% /srv/node/d2
/dev/sda7        50G  389M   50G   1% /srv/node/d3
```
| swift2 | 169.58.108.86 | 10.0.0.2 | 10.0.4.2 | 10.0.8.2 | no | 3/3 | Enforcing | active |
### swift2
```
SEL=Enforcing
KA=active
VIP=0
M=111

/dev/sda5        50G  389M   50G   1% /srv/node/d1
/dev/sda6        50G  389M   50G   1% /srv/node/d2
/dev/sda7        50G  389M   50G   1% /srv/node/d3
```
| swift3 | 169.58.108.87 | 10.0.0.3 | 10.0.4.3 | 10.0.8.3 | no | 3/3 | Enforcing | active |
### swift3
```
SEL=Enforcing
KA=active
VIP=0
M=111

/dev/sda5        50G  389M   50G   1% /srv/node/d1
/dev/sda6        50G  389M   50G   1% /srv/node/d2
/dev/sda7        50G  389M   50G   1% /srv/node/d3
```
| swift4 | 169.58.108.121 | 10.0.0.4 | 10.0.4.4 | 10.0.8.4 | no | 3/3 | Enforcing | active |
### swift4
```
SEL=Enforcing
KA=active
VIP=0
M=111

/dev/sda5        50G  389M   50G   1% /srv/node/d1
/dev/sda6        50G  389M   50G   1% /srv/node/d2
/dev/sda7        50G  389M   50G   1% /srv/node/d3
```

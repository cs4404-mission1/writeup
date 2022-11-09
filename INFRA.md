# Infrastructure

We configured our VMs as follows:

1. Voting API and web UI
2. DNS Resolver
3. Certificate authority and key server
4. Attacker

## Configure DNS Server

The DNS server simply serves to answer authoritatively for the `.internal` top level domain. We chose the `unbound` DNS resolver package - a notable departure from an industry standard authoritative DNS server like BIND, NSD, or Knot. Unbound is premierely a recursive resolver, but supports serving static local zones authoritatively and uses a single simple configuration file.

Update `apt` cache and install `unbound` package:

```bash
dns:~$ sudo apt update
dns:~$ sudo apt install -y unbound
```

Replace the `/etc/unbound/unbound.conf` config file:

```yaml
server:
  do-ip4: yes
  do-ip6: yes
  do-udp: yes

  directory: "/etc/unbound"
  interface: 0.0.0.0@53
  access-control: 0.0.0.0/0 allow
  verbosity: 3

  local-zone: "internal." static
    local-data: "api.internal IN A 10.64.10.1"
    local-data: "dns.internal IN A 10.64.10.2"
    local-data: "ca.internal IN A 10.64.10.3"
    local-data: "keyserver.internal IN A 172.16.10.1"
    local-data: "attacker.internal IN A 10.64.10.4"
    local-data: "_acme-challenge.admin.internal. IN TXT real-acme-response"

  local-zone: "10.16.172.in-addr.arpa." static
    local-data: "1.10.16.172.in-addr.arpa. IN PTR keyserver.internal."
    local-data: "2.10.16.172.in-addr.arpa. IN PTR api.internal."
```

Disable system resolver (which conflicts with the unbound listener on port 53), start and enable unbound start at boot:

```bash
dns:~$ sudo systemctl disable --now systemd-resolved
Removed /etc/systemd/system/dbus-org.freedesktop.resolve1.service.
Removed /etc/systemd/system/multi-user.target.wants/systemd-resolved.service.
dns:~$ sudo systemctl enable --now unbound
Synchronizing state of unbound.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable unbound
```

Next, we configure each VM to use the DNS server as it's resolver by overriding the DHCP behavior to ignore DNS and set a static list of resolver IPs in `/etc/netplan/00-installer-config.yaml`

```yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
      dhcp4-overrides:
        use-dns: no
      nameservers:
        addresses: [10.64.10.2]
```

## Configure Certificate Authority

The certificate authority runs a custom ACME protocol implementation that we developed in Go. First, we create a systemd unit file to govern program lifecycle, stored in `/etc/systemd/system/ca.service:`

```
[Unit]
Description=Certification Authority
After=network.target

[Service]
User=student
Group=student
ExecStart=/home/student/ca -listen 10.64.10.3:443
WorkingDirectory=/home/student/
AmbientCapabilities=CAP_NET_BIND_SERVICE
KillMode=process
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
```

The program can be compiled and built with `make -B ca` after cloning `https://github.com/cs4404-mission1/ca`.

```bash
mission1/ca(main) $ make -B ca
cd ca && CGO_LDFLAGS="-Xlinker -static" go build -o ca
# github.com/cs4404-mission1/ca
/usr/bin/ld: /tmp/go-link-1725924403/000004.o: in function `_cgo_2ac87069779a_C2func_getaddrinfo':
/tmp/go-build/cgo-gcc-prolog:58: warning: Using 'getaddrinfo' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
scp -i ~/.ssh/keys/wpi -P 8236 ca/ca student@secnet-gateway.cs.wpi.edu:~/
ca                                                      100%   11MB   8.5MB/s   00:01    
ssh -p 8236 -i ~/.ssh/keys/wpi student@secnet-gateway.cs.wpi.edu sudo systemctl restart ca
scp -i ~/.ssh/keys/wpi -P 8236 ca/main.go student@secnet-gateway.cs.wpi.edu:~/
main.go                                                 100% 4369   688.2KB/s   00:00    
scp -i ~/.ssh/keys/wpi -P 8236 ca/crypto.go student@secnet-gateway.cs.wpi.edu:~/
crypto.go                                               100% 3255   458.1KB/s   00:00    
scp -i ~/.ssh/keys/wpi -P 8236 ca/challenge.go student@secnet-gateway.cs.wpi.edu:~/
challenge.go                                            100% 1374   256.1KB/s   00:00    
```

The Makefile automatically builds a static binary called `ca` and copies it to the API VM along with program's source code. Finally, we reload systemd and start and enable the CA service:

```bash
ca:~$ sudo systemctl daemon-reload
ca:~$ sudo systemctl enable --now ca
```

Upon first execution, the CA generates it's root key and certificate, as well as a signed certificate for `ca.internal` and `keyserver.internal`. The root certificate will be saved as `ca-crt.pem` on the CA, and must be copied to the rest of the VMs to add to their trust store:

```bash
sudo cp ca-crt.pem /etc/ssl/certs/DigiShue_Root_CA.pem
sudo update-ca-certificates --fresh
```

## Setup key server VLAN

For security, the key server and API communicate on an isolated VLAN. We create a VLAN on the CA and API to facilitate this communication, and add an IP address to each:

CA:
```bash
ca:~$ sudo ip link add link ens3 name ens3.10 type vlan id 10
ca:~$ sudo ip addr add dev ens3.10 172.16.10.1/24
ca:~$ sudo ip link set dev ens3.10 up
```

API:
```bash
api:~$ sudo ip link add link ens3 name ens3.10 type vlan id 10
api:~$ sudo ip addr add dev ens3.10 172.16.10.2/24
api:~$ sudo ip link set dev ens3.10 up
```

## Deploy key server

The key server runs on the same VM as the CA, but binds to a different address (`172.16.10.1`) and has a different hostname (`keyserver.internal`). We first create a systemd unit file for the key server in `/etc/systemd/system/keyserv.service`:

```
[Unit]
Description=Key Server
After=network.target

[Service]
User=student
Group=student
ExecStart=/home/student/keysrv
WorkingDirectory=/home/student/
AmbientCapabilities=CAP_NET_BIND_SERVICE
KillMode=process
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
```

We then run `sudo systemctl daemon-reload` to sync the changes to systemd.

Cloning the key server repo with `git clone https://github.com/cs4404-mission1/keyserver` and running `make` within the directory will build, deploy, and restart the key server:

```bash
mission1/keyserver(main) $ make
CGO_LDFLAGS="-Xlinker -static" go build -o keysrv keysrv.go
# command-line-arguments
/usr/bin/ld: /tmp/go-link-2985185640/000004.o: in function `_cgo_2ac87069779a_C2func_getaddrinfo':
/tmp/go-build/cgo-gcc-prolog:58: warning: Using 'getaddrinfo' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
ssh -i ~/.ssh/keys/wpi -p 8236 student@secnet-gateway.cs.wpi.edu sudo systemctl stop keysrv
scp -i ~/.ssh/keys/wpi -P 8236 keysrv student@secnet-gateway.cs.wpi.edu:~/
keysrv                                                  100% 7546KB   5.9MB/s   00:01    
ssh -i ~/.ssh/keys/wpi -p 8236 student@secnet-gateway.cs.wpi.edu sudo systemctl start keysrv
```

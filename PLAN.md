# CS4404 Mission 1

- Compromise CA by requesting a cert for the attacker's machine, correctly validating the ACME challenge to get a cert for the attacker. Use it to authenticate with mTLS.
- Now we can use the client's private key to authenticate to the tabulator API
- Watch the tabulator API and wait until it's a "good" time to invalidate the cached tokens
- Crash the database or API to invalidate cached access tokens in API memory and/or ephemeral vote data

- VLAN hop to get on the same L2 as the webserver
- ARP spoof the webserver to get it to send traffic to us

## Attack Sequence

1. Use path traversal to obtain source code to the CA server
2. Notice RNG vuln, use it to predict the DNS message ID
3. DNS spoof with the known message ID
4. Use an ACME client to request a cert for the keyserver
5. VLAN hop into the webserver's network
6. xxxxxxxxxx sudo ip link add link ens3 name ens3.10 type vlan id 10sudo ip addr add dev ens3.10 172.16.10.2/24sudo ip link set dev ens3.10 upbash
7. ARP poison the webserver to make us look like the keyserver
8. Crash the webserver with lots of password attempts, which is computationally expensive because of argon2
9. Voting API will restart, fetch the new key, and invalidate all cached tokens
10. Login with a known credential to get a new token
11. Decrypt the token with the key we provided, now we know the current sequence number
12. Start spamming votes with the next n tokens
13. When a user logs in, their token is created but we're already voting so we get the vote first

## Mitigations

Defense in depth:

- Protect the CA network with a firewall (or any routed network segment)
- Protect admin API with a firewall
- Fix crash bug
- Fix in memory token storage

## Compromise CA

- Local File Inclusion to read CA source code
- Discover insecure RNG in DNS client IDs

https://editor.swagger.io/

# Appendix
## Appendix A
```rust
#[post("/login", data = "<user>")]
async fn userlogon(db: Connection<Vote>, state: &State<Persist>, cookies: &CookieJar<'_>, user: Form<User<'_>>) -> Redirect{
    let authok: bool;
    match hash_password(user.password.to_string()){ // argon 2 salt and hash
        Ok(hash) => {
            // retrieve the user record from sqlite
            match get_password(db, user.ssn).await{ 
                // authok is true if the known hash and entered password's hash match
                Some(tmp) => authok = hash == tmp, 
                None => authok = false,
            }
            },
        // If the user input fails automatic sanitization, send them back to login
        Err(_) => return Redirect::to(uri!(index())), 
    }
    if authok{
        println!("authentication OK");
        // get next auth number in sequence
        let rndm: String = (state.votekey.fetch_add(1, Ordering::Relaxed) + 1).to_string(); 
        // give client encrypted cookie with sequence number as payload
        cookies.add_private(Cookie::new("votertoken", rndm.clone())); 
        // tell authtoken thread to add new number to list of authorized keys
        state.rktsnd.send((1, rndm)).unwrap(); 
        // redirect authorized user to voting form
        return Redirect::to(uri!(vote()));
    }
    // redirect unauthorized user back to login
    Redirect::to(uri!(index()))
}
```
*Figure 1: part of the user authorization mechanism for the Vote API*

 ```rust
 #[post("/vote", data = "<vote>")]
async fn recordvote(mut db: Connection<Vote>, state: &State<Persist>, cookies: &CookieJar<'_>, vote: Form<Ballot<'_>>) -> Redirect{
    let mut status = 1;
    let key: String;
    // retrieve cookie from user
    match cookies.get_private("votertoken"){
        Some(crumb) => {
            // get auth sequence number from cookie
            key = crumb.value().to_string();
            // send verification request to authtoken thread
            state.rktsnd.send((0, key.clone())).unwrap();
            // wait for authtoken responce
            loop{
                let out = state.rktrcv.recv_timeout(Duration::from_millis(10)).unwrap();
                if out.1 == key{
                    status = out.0;
                    break;
                }
            }
            //remove cookie from user
            cookies.remove_private(crumb);
        }
        //if the user doesn't have a cookie, send them to login
        None => return Redirect::to(uri!(index())),
    }
    if status == 0{
        // run sql command to incriment vote tally for selected candidate (form input is santitized automatically)
        sqlx::query("UPDATE Votes SET count = (SELECT count FROM Votes WHERE name = ?)+1 WHERE name = ?;")
        .bind(vote.candidate).bind(vote.candidate).execute(&mut *db).await.unwrap();
        // tell authtoken thread to invalidate user's sequence number so a replay cannot be done
        state.rktsnd.send((2, key)).unwrap();
        // tell user everything worked
        Redirect::to(uri!(done()))
    }
    else{ 
    // assume something's gone wrong and direct user back to logon page
    Redirect::to(uri!(index()))
    }
    
}
 ```
*Figure 2: The main vote recording function of the Vote API, including token-based authorization*
## Appendix B
```zsh
Nmap scan report for api.internal (10.64.10.1)
Host is up (0.00027s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6340e54447875d36bdafeb67da7308c0 (RSA)
|   256 cc59f446f20997e2abdbe9c1052dcd7b (ECDSA)
|_  256 0db91dd0662428851aa2dee63f47a8bf (ED25519)
443/tcp open  ssl/https PWNED
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| ssl-cert: Subject: organizationName=DigiShue CA
| Subject Alternative Name: DNS:api.internal
| Issuer: organizationName=DigiShue CA
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-08T19:15:58
| Not valid after:  2032-11-08T19:15:58
| MD5:   8883885c9b57caa3248f0c15071e9eaa
|_SHA-1: 6d39e6bfea44b5201162ac5f4f1cb4696a722024
|_http-server-header: PWNED
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     content-type: text/html; charset=utf-8
|     server: PWNED
|     permissions-policy: interest-cohort=()
|     x-content-type-options: nosniff
|     x-frame-options: SAMEORIGIN
|     strict-transport-security: max-age=31536000
|     content-length: 564
|     <!DOCTYPE html>
|     <html lang="en">
|     <body>
|     <h1>Schueworld Public Web Network Election Database (PWNED)</h1>
|     <div>Please enter your credentials below to proceed.</div><br>
|     <form action="/login", method="post">
|     <label for="ssn">Social Security Number:</label><br>
|     <input type="text" id="ssn" name="ssn"><br>
|     <label for="password">Secret Passphrase from Mail:</label><br>
|     <input type="text" id="password" name="password">
|     <br>
|     <br><input type="submit" value="Submit">
|     </form>
|     <p>Please remember to enable cookies on this site!</p>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     content-type: text/html; charset=utf-8
|     server: PWNED
|     permissions-policy: interest-cohort=()
|     x-content-type-options: nosniff
|     x-frame-options: SAMEORIGIN
|     strict-transport-security: max-age=31536000
|     content-length: 383
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>404 Not Found</title>
|     </head>
|     <body align="center">
|     <div role="main" align="center">
|     <h1>404: Not Found</h1>
|     <p>The requested resource could not be found.</p>
|     </div>
|     <div role="contentinfo" align="center">
|     <small>Rocket</small>
|     </div>
|     </body>
|_    </html>
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port443-TCP:V=7.93%T=SSL%I=7%D=11/9%Time=636C63D3%P=x86_64-redhat-linux
SF:-gnu%r(GetRequest,34B,"HTTP/1\.0\x20200\x20OK\r\ncontent-type:\x20text/
SF:html;\x20charset=utf-8\r\nserver:\x20PWNED\r\npermissions-policy:\x20in
SF:terest-cohort=\(\)\r\nx-content-type-options:\x20nosniff\r\nx-frame-opt
SF:ions:\x20SAMEORIGIN\r\nstrict-transport-security:\x20max-age=31536000\r
SF:\ncontent-length:\x20564\r\ndate:\x20Thu,\x2010\x20Nov\x202022\x2002:37
SF::06\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n\n<body>\n
SF:\x20\x20<h1>Schueworld\x20Public\x20Web\x20Network\x20Election\x20Datab
SF:ase\x20\(PWNED\)</h1>\n\n\n\x20\x20<div>Please\x20enter\x20your\x20cred
SF:entials\x20below\x20to\x20proceed\.</div><br>\n\x20\x20<form\x20action=
SF:\"/login\",\x20method=\"post\">\n\x20\x20<label\x20for=\"ssn\">Social\x
SF:20Security\x20Number:</label><br>\n\x20\x20<input\x20type=\"text\"\x20i
SF:d=\"ssn\"\x20name=\"ssn\"><br>\n\n\x20\x20<label\x20for=\"password\">Se
SF:cret\x20Passphrase\x20from\x20Mail:</label><br>\n\x20\x20<input\x20type
SF:=\"text\"\x20id=\"password\"\x20name=\"password\">\n\x20\x20<br>\n\x20\
SF:x20<br><input\x20type=\"submit\"\x20value=\"Submit\">\n</form>\n<p>Plea
SF:se\x20remember\x20to\x20enable\x20cookies\x20on\x20this\x20site!</p>\n<
SF:/body>\n</html>\n\n")%r(HTTPOptions,29D,"HTTP/1\.0\x20404\x20Not\x20Fou
SF:nd\r\ncontent-type:\x20text/html;\x20charset=utf-8\r\nserver:\x20PWNED\
SF:r\npermissions-policy:\x20interest-cohort=\(\)\r\nx-content-type-option
SF:s:\x20nosniff\r\nx-frame-options:\x20SAMEORIGIN\r\nstrict-transport-sec
SF:urity:\x20max-age=31536000\r\ncontent-length:\x20383\r\ndate:\x20Thu,\x
SF:2010\x20Nov\x202022\x2002:37:06\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html
SF:\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n
SF:\x20\x20\x20\x20<title>404\x20Not\x20Found</title>\n</head>\n<body\x20a
SF:lign=\"center\">\n\x20\x20\x20\x20<div\x20role=\"main\"\x20align=\"cent
SF:er\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>404:\x20Not\x20Found</h1>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<p>The\x20requested\x20resource\x20could
SF:\x20not\x20be\x20found\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<hr\x20/>
SF:\n\x20\x20\x20\x20</div>\n\x20\x20\x20\x20<div\x20role=\"contentinfo\"\
SF:x20align=\"center\">\n\x20\x20\x20\x20\x20\x20\x20\x20<small>Rocket</sm
SF:all>\n\x20\x20\x20\x20</div>\n</body>\n</html>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 20.90 seconds
```
*Figure 1: nmap output of scan against api.internal*

```
{
	"Connection:": {
		"Protocol version:": "TLSv1.3",
		"Cipher suite:": "TLS_AES_128_GCM_SHA256",
		"Key Exchange Group:": "x25519",
		"Signature Scheme:": "RSA-PSS-SHA512"
	},
	"Host api.internal:": {
		"HTTP Strict Transport Security:": "Enabled",
		"Public Key Pinning:": "Disabled"
	},
	"Certificate:": {
		"Issued To": {
			"Common Name (CN):": "<Not Available>",
			"Organization (O):": "DigiShue CA",
			"Organizational Unit (OU):": "<Not Available>"
		},
		"Issued By": {
			"Common Name (CN):": "<Not Available>",
			"Organization (O):": "DigiShue CA",
			"Organizational Unit (OU):": "<Not Available>"
		},
		"Period of Validity": {
			"Begins On:": "Tue, 08 Nov 2022 19:15:58 GMT",
			"Expires On:": "Mon, 08 Nov 2032 19:15:58 GMT"
		},
		"Fingerprints": {
			"SHA-256 Fingerprint:": "F1:16:12:97:56:28:D6:E2:2D:ED:93:93:2D:8F:2A:14:02:E7:7E:A5:CA:F1:BB:87:40:2F:A1:1A:71:66:7F:7C",
			"SHA1 Fingerprint:": "6D:39:E6:BF:EA:44:B5:20:11:62:AC:5F:4F:1C:B4:69:6A:72:20:24"
		},
		"Transparency:": "<Not Available>"
	}
}
```
*Figure 2: HTTP security information - output by firefox developer tools*

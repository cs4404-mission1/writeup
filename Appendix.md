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
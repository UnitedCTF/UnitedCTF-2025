# Lost

## Write-up

Nothing more than a username, password, an ip address and a port is given which is intentionnal. It is up to you to understand what is the protocol being used behind the scenes.

By running the command `nc $IP $PORT`, you can see that it is the SSH protocol that is being used because of the string `SSH-2.0-...`.

```bash
nc $IP $PORT
SSH-2.0-🌎🛰️
```

You can communicate with the server via SSH using the command `ssh -p$PORT paul@$IP` then type the password `i_hope_you_wont_need_this`, but an error is returned: the channel of type 'session' is not supported.

```bash
ssh -p$PORT paul@$IP   
Warning: Permanently added '$IP:$PORT' (RSA) to the list of known hosts.
paul@$IP's password: 
channel 0: open failed: unknown channel type: unsupported channel type 'session'
Connection to $IP closed.
```

By adding `-v` to our ssh command, we can see that the server is trying to open a channel of type `whereareyou`.

```bash
ssh -v -p$PORT paul@$IP
...
debug1: Authentications that can continue: password
debug1: Next authentication method: password
paul@$IP's password: 
Authenticated to $IP ($IP:$PORT) using "password".
debug1: channel 0: new session [client-session] (inactive timeout: 0)
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_channel_open: ctype whereareyou rchan 0 win 2097152 max 32768
                     ^^^^^^^^^^^^        ^^^^^^^^^^^
debug1: failure whereareyou
                ^^^^^^^^^^^
Connection to $IP closed by remote host.
Connection to $IP closed.
...
```

The `ssh` command is not flexible enough to accept and communicate with arbitrary channels. We need to program our own SSH client. In the case of the solution, the language Go with the package `golang.org/x/crypto/ssh` is used to interact with the server.

In a nutshell, to obtain the flag, you have to:
1. Accept the `whereareyou` channel.
2. Send the string `polo` in the channel `whereareyou` (to answer the question `marco`).
3. A short message with a UUIDv4 will be sent in the channel `whereareyou` by the server.
4. In the main channel, send a request of type equal to the UUIDv4 in the last step.
5. Print the request reply payload to obtain the flag.

See the implemented solution [here](../src/cmd/solver/main.go), you can run it with the command `SSH_ADDR=$IP:$PORT go run ./cmd/solver/main.go` from the folder `src`.

## Flag

`flag-idk_where_you_are_but_heres_a_flag_for_your_trouble_4a1818496f8c0048`

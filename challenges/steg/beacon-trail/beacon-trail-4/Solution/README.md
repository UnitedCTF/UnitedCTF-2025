# The Beacon Trail 4

## Write-up

There is one flashing pillar when going forward.

The pillar is encoded in morse.

When decoding it, we get `dq6cu02j99p8zep8xjg8uum7f` which is the password of the zip file in the notes.

The file inside contains the string `-rrrr-dlllllllll-rrrtrrdrt-rddrrtr-lll-l-ttlll-dddrrrrt-rrr-ttlllllll-lll-drrrrrdrrr-l-trrrd-lllllllll-ttl-rrdrrdr-rrrrr-llllllllll-rrrrrrr-rrr-llllllllll-tt--`.

There is also a picture of a Dvorak keyboard in the game's file. The pillar give relative direction on that keyboard starting at the letter f (there is no other starting points that works). When getting each key at the `-` character, you get the flag.

## Flag

`flag-th4t-41nt-o1d-at-a11`
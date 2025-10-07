# The Beacon Trail 1

## Write-up

There is two flashing pillar at the beginning.

Due to the leftover notes, we can infer that `.` and `-` is morse with a timing of 0.5 second pulse and 2 seconds pulse respectively and `0` and `1` is binary with a timing of two 0.1 second pulse and one 1 second pulse respectively.

The left one is encoded in binary. The binary message is `00110000 01101100 01100100 00101101 01100010 00110001 01101110 01100001 01110010 01111001 00101101 01101001 00101101 00110100 01101101` and the text is `0ld-b1nary-i-4m`.

The second one is encoded in morse. The morse message is `..-. .-.. .- --. -....- - .... .---- ... -....- .---- ..... -....- ....- -. -.-. .---- ...-- -. - -....- -- ----- .-. ... ...--` and the text is `flag-th1s-15-4nc13nt-m0rs3`.

## Flag

`flag-th1s-15-4nc13nt-m0rs3`
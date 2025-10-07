# The Beacon Trail 3

## Write-up

There is one flashing pillar when going forward then right.

The pillar is encoded in raw binary - there are no encoding specifically.

When decoding it, we get `1010110100101101010010110011011010011010101010110011010100101100110110011010101010110011001010101001011001100101010011010101010110010101010011011011001011010010110100101001101010100101101010010`

The challenge message tells us that this is some 'art', so an image. The dimension is not given but knowing that the message is 193 bits long (it's a prime number) there ain't a lot of possibility. Every `1` is a white pixel and `0` a black one. This form a group of pixel which true shape is 1x193. This image is a morse code by itself and gives the final flag.

The generated image should be ![this one](result.bmp)

## Flag

`flag-dam-thats-horrible`
# Curse of the Pharaoh 2

## Write-up

This flag was in the code of the game. To access it, just use a .NET assembly editor like dnSpy and open Assembly-CSharp.dll. The flag is in the "PrintFlagSystem.cs" file. It's base64 encoded, so just base64 decode it and you get the flag.

## Flag

`flag-H0w_d1D_y0u_G37_H3rE?`

def vig_bruteforce(input):
    def _vigenere_dec(inp, key):
        inp = inp.lower()
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        key_length = len(key)
        key_as_int = [alphabet.index(i) for i in key.lower()]
        input_int = [alphabet.index(i) for i in inp if i in alphabet]
        output = ""
        for i in range(len(input_int)):
            value = (input_int[i] - key_as_int[i % key_length]) % 26
            output += alphabet[value]
        return output

    key = "COL?%SU$L!R)/Z"
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for CHAR_1 in alphabet:
        sk = f"COL{CHAR_1}"
        if _vigenere_dec(input[0:4], sk) == "flag":
            break
    for i1 in alphabet:
        for i2 in alphabet:
            for i3 in alphabet:
                for i4 in alphabet:
                    for i5 in alphabet:
                        nkey = (
                            key.replace("?", CHAR_1)
                            .replace("%", i1)
                            .replace("$", i2)
                            .replace("!", i3)
                            .replace(")", i4)
                            .replace("/", i5)
                        )
                        res = _vigenere_dec(input, nkey)
                        if "flagunitedctf" in res:
                            return res


inp = "hzlu-mfclprtxs-zqnduaglg-ecrwt-ns-vttvoa"
print(vig_bruteforce(inp))

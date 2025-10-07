from Crypto.Util.number import long_to_bytes,bytes_to_long

def i_root(x,exp):
    low, high = 0, x
    while low <= high:
        mid = (low + high) // 2
        root = mid**exp
        if root == x:
            return mid
        elif root < x:
            low = mid + 1
        else:
            high = mid - 1
    return high

cipher = bytes.fromhex("113715c135192f3060a2fec7a16bd1b496021b056e207ccfad4197d1db2d38fce5fa39f214cad93a567fe72c4a455d9631cf963bc14effa1bb705d698d50b525c1b66e46b9e4dd5360a86f2dae2f0a97fb0f8f6ea4b27774018f5129eb702382fc14f56c79ba55615e699f38c7db388833bebc63f34e6e0d4c683dd297cb361fd753aa6186a282280b0c9fe88965185198c8589829d3c84746706352a2daa72e9f1fc8c4a815adf9f95dd5cae3f7ab7e052c564def190a2880d422a253d3ad53d194fde95b3654de05069464636ad70373ef9582537eddfb70e9d7b71d1ab5617a680cb7907d5109e852f3b96e1871578d07c51992e1eb6e37d8fe57eb8c37641c7db6b80471c1cec9d4513b0cb5a4d21652e432271e1d31cd963c665bc9fce3f1dd7b14e127e9ce7ad12ebcf5251e1250fb8aa49c5e07b0fe1fc9994b13688e8bf48f21af9ffdcb8b8c030005a7df53261d743274b76c8ce6af022286e6e3917820f4d09bb75b1b4f0f0e3fcacdc115")
m_recovered = i_root(bytes_to_long(cipher),9)
flag_recovered = long_to_bytes(m_recovered)
print(f"CRACKED: {flag_recovered.decode()}")
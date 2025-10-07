import pwnlib.tubes.remote as remote

nc = "127.0.0.1"
port = 1439
r = remote.remote(nc, port)


def readline(endOfLine="\n"):
    data = b""
    rec = ""
    while rec != bytes(endOfLine, "utf-8"):
        rec = r.recvn(1)
        data += rec
    return data.decode()


def readall():
    rec = r.recvall(timeout=1)
    return rec.decode()


def sendline(toSend):
    r.send(f"{toSend}\n".encode())



def get_subtract_mapping(nums, ops):
    candidates = []
    for op in ops:
        if op == "(":
            continue
        if op == ")":
            continue
        sendline(f"{nums[0]}{op}{nums[0]}")
        res = r.recvlines(10)
        answer = res[-8].decode().split(":")[-1].strip()
        result = int(answer) if answer.lstrip("-").isdigit() else None
        if result == 0:
            candidates.append(op)
    if len(candidates) == 1:
        return candidates[0]

    for op in candidates:
        sendline(f"{nums[0]}{op}{nums[1]}")
        res = r.recvlines(10)
        answer = res[-8].decode().split(":")[-1].strip()
        result1 = int(answer) if answer.lstrip("-").isdigit() else None

        if result1 is None:
            continue

        sendline(f"{nums[1]}{op}{nums[0]}")
        res = r.recvlines(10)
        answer = res[-8].decode().split(":")[-1].strip()
        result2 = int(answer) if answer.lstrip("-").isdigit() else None

        if result2 is None:
            continue

        if result1 < 0 or result2 < 0:
            return op

    raise Exception("Couldn't find mapping for -")


def subtract(a, b):
    sendline(f"{a}{subtract_mapping}{b}")
    res = r.recvlines(10)
    idx = [i for i, line in enumerate(res) if b"Your result:" in line]
    answer = res[idx[0]].decode().split(":")[-1].strip()
    result = int(answer)
    return result


def get_biggest_num(nums):
    candidate = nums[0]
    for v in nums[1:]:
        if subtract(v, candidate) > 0:
            candidate = v
    return candidate


def find_index_of_zero(nums: list[int]):
    if 0 not in nums:
        return -1

    for i in nums:
        if subtract(biggest_num, i) == max(nums):
            return nums.index(i)


def get_zero(nums):
    if zero_idx == 0:
        return f"({nums[-1]}-{nums[-1]})"

    return f"({nums[0]}-{nums[0]})"


def get_one(nums, ops):
    if 1 in nums:
        for i in nums:
            if subtract(biggest_num, i) == max(nums) - 1:
                return str(i)
    if "/" in ops:
        if zero_idx == 0:
            return f"({nums[-1]}/{nums[-1]})"
        return f"({nums[0]}/{nums[0]})"
    if "-" in ops:
        for i in range(len(nums) - 1):
            for j in range(i + 1, len(nums)):
                res = subtract(nums[j], nums[i])
                if res == 1:
                    return f"({nums[j]}-{nums[i]})"
                if res == -1:
                    return f"({nums[i]}-{nums[j]})"
    
    raise Exception("Couldn't find 1")


def get_all_ops_mappings(nums, ops):
    mappings = {}
    biggest_value = max(nums)
    for op in ops:
        if op == "(":
            mappings[op] = "("
            continue

        if op == ")":
            mappings[op] = ")"
            continue

        sendline(f"{biggest_num}{op}{biggest_num}")
        res = r.recvlines(10)
        answer = res[-8].decode().split(":")[-1].strip()
        result = int(answer) if answer.lstrip("-").isdigit() else None
        if result == biggest_value * biggest_value:
            mappings["*"] = op
        if result == 1:
            mappings["/"] = op
        if result == biggest_value * 2:
            mappings["+"] = op
        if result == 0:
            if op is subtract_mapping:
                mappings["-"] = op
            else:
                mappings["%"] = op
    return mappings


def use_all_operators(nums, ops):
    zero = get_zero(nums)
    useless_chain = ""
    for op in ops:
        match op:
            case "+":
                useless_chain += f"+{zero}"
            case "-":
                useless_chain += f"-{zero}"
            case "*":
                useless_chain += f"*{one}"
            case "/":
                useless_chain += f"/{one}"
            case "%":
                useless_chain += f"--({one}%{one})"
    return useless_chain


def real_eval(new_eq, nums):
    mapping = {str(biggest_num): str(max(nums)), one: "1"}
    if len(one) == 1:
        eq = new_eq.translate(str.maketrans(mapping))
    else:
        n_one = one.replace(str(biggest_num), str(max(nums)))
        eq = new_eq.replace(str(biggest_num), str(max(nums))).replace(n_one, "1")
    return eval(eq)


def get_equation(
    last_eq: str, last_res: int, expected: int, nums: list[int], ops: list[str]
):
    def _get_biggest_operator(ops):
        if "*" in ops or "/" in ops:
            if "*" in ops:
                return "*"
            return "/"
        if "+" in ops:
            return "+"
        return "-"

    biggest_op = _get_biggest_operator(ops)

    if last_res == expected:
        return last_eq + use_all_operators(nums, ops)

    if last_res < expected:

        if expected - last_res < max(nums):

            diff = int(expected - last_res)
            add_eq = f"+{one}" * diff if "+" in ops else f"--{one}" * diff
            new_eq = f"({last_eq}){add_eq}"
            new_res = real_eval(new_eq, nums)

            return get_equation(new_eq, new_res, expected, nums, ops)

        if biggest_op == "*":
            add_eq = f"*{biggest_num}"
        elif biggest_op == "/":
            add_eq = f"//({one}/{biggest_num})"
        elif biggest_op == "+":
            add_eq = f"+{biggest_num}"
        else:
            add_eq = f"-({one}-{biggest_num})"

        new_eq = f"({last_eq}){add_eq}"

        new_res = real_eval(new_eq, nums)

        return get_equation(new_eq, new_res, expected, nums, ops)

    diff = int(last_res - expected)

    if diff > max(nums):
        mult = int(diff // max(nums))
        remainder = int(diff % max(nums))
        add_eq = f"-{biggest_num}" * mult
        if remainder > 0:
            if "+" in ops:
                add_eq += f"+{one}" * remainder
            else:
                add_eq += f"--{one}" * remainder
        new_eq = f"({last_eq}){add_eq}"
        new_res = real_eval(new_eq, nums)

        return get_equation(new_eq, new_res, expected, nums, ops)

    add_eq = f"-{one}" * diff
    new_eq = f"({last_eq}){add_eq}"
    new_res = real_eval(new_eq, nums)

    return get_equation(new_eq, new_res, expected, nums, ops)



def solve_one():
    r.recvuntil(b"The expected result is:")
    expected = int(r.recvline().strip())
    r.recvuntil(b"Allowed numbers:")
    nums = sorted([int(x.strip()) for x in r.recvline().decode().strip().split(",")])
    r.recvuntil(b"Allowed operators:")
    ops = [x.strip() for x in r.recvline().decode().strip().split(" ")]

    global subtract_mapping
    subtract_mapping = get_subtract_mapping(nums, ops)

    global biggest_num
    biggest_num = get_biggest_num(nums)

    global zero_idx
    zero_idx = find_index_of_zero(nums)

    global one
    one = get_one(nums, ops)

    global op_mappings
    op_mappings = get_all_ops_mappings(nums, ops)

    eq = get_equation(one, 1, expected, nums, ops)
    eq = eq.translate(str.maketrans(op_mappings))

    sendline(eq)
    
for _ in range(3):
    solve_one()
print(readall())

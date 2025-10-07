import pwnlib.tubes.remote as remote

nc = "127.0.0.1"
port = 1437
r = remote.remote(nc, port)


def readall():
    rec = r.recvall(timeout=1)
    return rec.decode()


def sendline(toSend):
    r.send(f"{toSend}\n".encode())


def get_zero(nums):
    if 0 in nums:
        return "0"
    return f"({nums[0]}-{nums[0]})"


def get_one(nums, ops):
    if 1 in nums:
        return "1"
    if "/" in ops:
        return f"({nums[-1]}/{nums[-1]})"
    if "-" in ops:
        for i in range(len(nums) - 1):
            if nums[i + 1] - nums[i] == 1:
                return f"({nums[i+1]}-{nums[i]})"
    if "%" in ops:
        for i in range(len(nums) - 1):
            if nums[i] == 0:
                continue
            for j in range(i + 1, len(nums)):
                if nums[j] % nums[i] == 1:
                    return f"({nums[j]}%{nums[i]})"
    raise Exception("Couldn't find 1")


def use_all_operators(nums, ops):
    zero = get_zero(nums)
    one = get_one(nums, ops)
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

    one = get_one(nums, ops)

    biggest_op = _get_biggest_operator(ops)
    biggest_num = max(nums)

    if last_res == expected:
        return last_eq + use_all_operators(nums, ops)

    if last_res < expected:

        if expected - last_res < biggest_num:

            diff = int(expected - last_res)
            add_eq = f"+{one}" * diff if "+" in ops else f"--{one}" * diff
            new_eq = f"({last_eq}){add_eq}"
            new_res = eval(new_eq)

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

        new_res = eval(new_eq)

        return get_equation(new_eq, new_res, expected, nums, ops)

    diff = int(last_res - expected)

    if diff > biggest_num:
        mult = int(diff // biggest_num)
        remainder = int(diff % biggest_num)
        add_eq = f"-{biggest_num}" * mult
        if remainder > 0:
            if "+" in ops:
                add_eq += f"+{one}" * remainder
            else:
                add_eq += f"--{one}" * remainder
        new_eq = f"({last_eq}){add_eq}"
        new_res = eval(new_eq)

        return get_equation(new_eq, new_res, expected, nums, ops)

    add_eq = f"-{one}" * diff
    new_eq = f"({last_eq}){add_eq}"
    new_res = eval(new_eq)

    return get_equation(new_eq, new_res, expected, nums, ops)


def solve_one():
    r.recvuntil(b"The expected result is:")
    expected = int(r.recvline().strip())
    r.recvuntil(b"Allowed numbers:")
    nums = sorted([int(x.strip()) for x in r.recvline().decode().strip().split(",")])
    r.recvuntil(b"Allowed operators:")
    ops = [x.strip() for x in r.recvline().decode().strip().split(" ")]

    one = get_one(nums, ops)

    eq = get_equation(one, 1, expected, nums, ops)
    sendline(eq)


for _ in range(3):
    solve_one()
print(readall())

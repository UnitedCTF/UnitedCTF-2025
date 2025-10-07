from random import randint, sample
from main import main_loop, scramble


def get_level():
    expected = randint(100, 999)
    allowed_nums = randint(5, 7)
    allowed_ops = randint(1, 2)
    available_nums = [str(x) for x in range(10)]
    available_ops = ["*", "/", "%"]

    num_choices = sample(available_nums, k=allowed_nums)
    op_choices = sample(available_ops, k=allowed_ops) + ["-"]
    allowed = {
        "numbers": num_choices,
        "operators": op_choices + ["(", ")"],
    }
    mapping = {
        "numbers": dict(zip(num_choices, scramble(num_choices))),
        "operators": dict(zip(op_choices + ["(", ")"], scramble(op_choices) + ["(", ")"])),
    }
    return expected, allowed, mapping


main_loop(get_level)


from os import getenv, _exit

from threading import Timer
from random import shuffle
from typing import Callable


def _level_loop(level: Callable, timer: Timer):
    expected_result, allowed, mapping = level()

    def apply_mapping(equation: str, mapping: dict):
        eq = equation.translate(str.maketrans(mapping["numbers"]))
        eq = eq.translate(str.maketrans(mapping["operators"]))
        return eq

    while True:
        print(f"The expected result is: {expected_result}")
        print(f"Allowed numbers: {', '.join(allowed['numbers'])}")
        print(f"Allowed operators: {' '.join(allowed['operators'])}")
        user_input = input("Please enter your equation: ")

        if user_input.strip() == "":
            print("Empty input!")
            continue

        user_input = "".join(user_input.split())

        if not set(user_input).issubset(allowed["numbers"] + allowed["operators"]):
            print("Invalid equation!\n")
            continue

        if not set(user_input.replace("(", "").replace(")", "")).intersection(
            allowed["operators"]
        ):
            print("Invalid equation!\n")
            continue

        if str(expected_result) in user_input:
            print("You can't have the expected result in your equation!\n")
            continue

        user_input = apply_mapping(user_input, mapping)

        try:
            eval_result = eval(user_input, {}, {})
        except Exception as e:
            print(f"Error evaluating your equation: {e}\n")
            eval_result = None

        print()
        print("-" * 20 + " Output " + "-" * 20)
        print(
            f"Your result: {int(eval_result) if eval_result is not None else 'Error'}"
        )
        print(f"Expected result: {expected_result}")
        print("-" * 48)
        print()

        if int(eval_result if eval_result is not None else -1) == expected_result:
            if not set(allowed["operators"]).issubset(set(user_input)):
                print(
                    "You must use all allowed operators at least once if you want the flag!\n"
                )
                continue

            print("Correct!")
            return True
        print("Incorrect!")


def main_loop(level: Callable):
    print("\nYou have 3 seconds to find 3 equation.\n")

    def timer_interrupt():
        print("\n\nTimeout! You took too long to respond.")
        from sys import stdout
        stdout.flush()
        _exit(0)

    timer = Timer(3, timer_interrupt)
    timer.start()
    for i in range(3):
        print(f"# {i+1} #")
        print(f"-" * 20)
        res = _level_loop(level, timer)
        print(f"-" * 20)
        if not res:
            print("You failed!")
            _exit(0)
    print("Flag: " + getenv("FLAG"))
    timer.cancel()


def scramble(lst):
    shuffled = lst[:]
    shuffle(shuffled)
    return shuffled

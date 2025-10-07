from core.enums import Register
from core.objects.arguments import Argument
from core.objects.context import Context
from core.objects.commands import ContextAwareCommand


class SetValueCommand(ContextAwareCommand):
    """
    Set a value in a register.
    """

    command_id = 0x5
    expected_args = [
        Argument("value", int),
        Argument("register", Register),
    ]

    def __init__(self, context: Context, value: bytes, register: bytes):
        super().__init__(context)
        self.add_argument("value", value)
        self.add_argument("register", register)


class AddValueCommand(ContextAwareCommand):
    """
    Add a value to a register.
    """

    command_id = 0x6
    expected_args = [
        Argument("value", int),
        Argument("register", Register),
    ]

    def __init__(self, context: Context, value: bytes, register: bytes):
        super().__init__(context)
        self.add_argument("value", value)
        self.add_argument("register", register)


class CreateStringCommand(ContextAwareCommand):
    """
    Create a string in the data section and loads it into a register.
    """

    command_id = 0xB
    expected_args = [
        Argument("string", str),
        Argument("register", Register),
        Argument("id", int, priority=1),
    ]

    def __init__(self, context: Context, string: bytes, register: bytes, id: bytes):
        super().__init__(context)
        self.add_argument("string", string, id)
        self.add_argument("register", register)
        self.add_argument("id", id)

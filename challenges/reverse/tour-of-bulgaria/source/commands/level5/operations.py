from core.objects.arguments import BigInt
from core.enums import Register
from core.objects.arguments import Argument
from core.objects.context import Context
from core.objects.commands import ContextAwareCommand
from core.objects.types import BigInt

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


class LoadFromBufferCommand(ContextAwareCommand):
    """
    Load 8 bytes into a register.
    """

    command_id = 0xD
    expected_args = [
        Argument("buffer_location", Register),
        Argument("offset", int),
        Argument("register", Register),
    ]

    def __init__(self, context: Context, buffer_location: bytes, offset: bytes, register: bytes):
        super().__init__(context)
        self.add_argument("buffer_location", buffer_location)
        self.add_argument("offset", offset)
        self.add_argument("register", register)

class AddValueCommand(ContextAwareCommand):
    """
    Add a value to a register.
    """

    command_id = 0x6
    expected_args = [
        Argument("value", BigInt),
        Argument("register", Register),
    ]

    def __init__(self, context: Context, value: bytes, register: bytes):
        super().__init__(context)
        self.add_argument("value", value)
        self.add_argument("register", register)


class XORValueCommand(ContextAwareCommand):
    """
    XOR a value with a register.
    """

    command_id = 0xB
    expected_args = [
        Argument("key", BigInt),
        Argument("register", Register),
    ]

    def __init__(self, context: Context, key: bytes, register: bytes):
        super().__init__(context)
        self.add_argument("key", key)
        self.add_argument("register", register)


class XORFromRegisterCommand(ContextAwareCommand):
    """
    XOR a register with a register.
    """

    command_id = 0xBB
    expected_args = [
        Argument("key", Register),
        Argument("register", Register),
    ]

    def __init__(self, context: Context, key: bytes, register: bytes):
        self.magic_number = 0xB
        super().__init__(context)
        self.add_argument("key", key)
        self.add_argument("register", register)


class CreateStringCommand(ContextAwareCommand):
    """
    Create a string in the data section and loads it into a register.
    """

    command_id = 0xC
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

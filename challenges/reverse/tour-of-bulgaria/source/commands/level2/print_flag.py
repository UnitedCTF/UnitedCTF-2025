from typing import override

from core.enums import Register
from core.objects.arguments import Argument
from core.objects.commands import ContextAwareCommand
from core.objects.context import Context


class PrintFlagCommand(ContextAwareCommand):
    """
    Print the flag.
    """

    command_id = 0x99
    expected_args = [
        Argument("key", int),
        Argument("register", Register),
    ]

    def __init__(self, context: Context, key: bytes, register: bytes):
        super().__init__(context)
        self.add_argument("key", key)
        self.add_argument("register", register)

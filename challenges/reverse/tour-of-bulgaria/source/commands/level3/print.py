from typing import overload, override

from core.objects.commands import ContextAwareCommand
from core.objects.context import Context
from core.enums import Register
from core.objects.arguments import Argument


class PrintCommand(ContextAwareCommand):
    """
    Print a string to the console.
    """

    command_id = 0x4
    expected_args = [
        Argument("size", int),
        Argument("buffer_location", Register),
    ]

    def __init__(self, context: Context, size: bytes, buffer_location: bytes):
        super().__init__(context)
        self.add_argument("size", size)
        self.add_argument("buffer_location", buffer_location)

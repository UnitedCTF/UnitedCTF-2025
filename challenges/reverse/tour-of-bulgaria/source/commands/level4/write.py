from typing import overload, override

from core.objects.commands import ContextAwareCommand
from core.objects.context import Context
from core.enums import Register
from core.objects.arguments import Argument


class WriteCommand(ContextAwareCommand):
    """
    write a string to a file descriptor.
    """

    command_id = 0x4
    expected_args = [
        Argument("size", int),
        Argument("buffer_location", Register),
        Argument("file_descriptor_location", Register),
    ]

    def __init__(
        self,
        context: Context,
        size: bytes,
        buffer_location: bytes,
        file_descriptor_location: bytes,
    ):
        super().__init__(context)
        self.add_argument("size", size)
        self.add_argument("buffer_location", buffer_location)
        self.add_argument("file_descriptor_location", file_descriptor_location)

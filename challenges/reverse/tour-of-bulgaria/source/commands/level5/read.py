from typing import override
from core.objects.commands import ContextAwareCommand
from core.objects.context import Context
from core.enums import Register
from core.objects.arguments import Argument


class ReadCommand(ContextAwareCommand):
    """
    Read from a file descriptor into a pointer.
    
    size: The number of bytes to read.
    file_descriptor_location: The register containing the file descriptor.
    buffer_location: The register containing the pointer to the buffer where the data will be read into.
    
    """

    command_id = 0x3
    expected_args = [
        Argument("size", int),
        Argument("file_descriptor_location", Register),
        Argument("buffer_location", Register),
    ]

    def __init__(
        self,
        context: Context,
        size: bytes,
        file_descriptor_location: bytes,
        buffer_location: bytes,
    ):
        super().__init__(context)
        self.add_argument("size", size)
        self.add_argument(
            "file_descriptor_location",
            file_descriptor_location,
        )
        self.add_argument(
            "buffer_location",
            buffer_location,
        )

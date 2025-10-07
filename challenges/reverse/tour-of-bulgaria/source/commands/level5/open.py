from typing import overload, override

from core.objects.commands import ContextAwareCommand
from core.objects.context import Context
from core.enums import Register
from core.objects.arguments import Argument


class OpenCommand(ContextAwareCommand):
    """
    Open a file. 
    
    filename: The name of the file to open.
    mode: The mode to open the file in (0 for read, 1 for write, 2 for both).
    result_register: The register to store the file descriptor.
    
    """

    command_id = 0x1
    expected_args = [
        Argument("filename", str),
        Argument("mode", int),
        Argument("result_register", Register),
    ]

    def __init__(
        self, context: Context, filename: bytes, mode: bytes, result_register: bytes
    ):
        super().__init__(context)
        self.add_argument("filename", filename)
        self.add_argument("mode", mode)
        self.add_argument("result_register", result_register)

    @override
    def validate(self) -> bool:
        if not super().validate():
            return False

        arg = self.get_argument("result_register")
        if not Register.is_valid(arg.value.value):
            return False

        arg = self.get_argument("mode")
        if arg.value not in [0, 1, 2]:
            return False
        return True

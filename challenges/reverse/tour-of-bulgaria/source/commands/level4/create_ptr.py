from typing import override

from core.objects.commands import ContextAwareCommand
from core.objects.context import Context
from core.enums import Register
from core.objects.arguments import Argument


class CreatePtrCommand(ContextAwareCommand):
    """
    Create a pointer to a memory location.

    ! Careful, this command overwrites the r10 register !
    """

    command_id = 0x2
    expected_args = [
        Argument("size", int),
        Argument("result_register", Register),
    ]

    def __init__(self, context: Context, size: bytes, result_register: bytes):
        super().__init__(context)
        self.add_argument("size", size)
        self.add_argument("result_register", result_register)

    @override
    def validate(self) -> bool:
        if not super().validate():
            return False

        arg = self.get_argument("size")
        if arg.value <= 0 or arg.value > 4096:
            return False
        return True

from core.objects.arguments import Argument
from core.objects.context import Context
from core.objects.commands import ContextAwareCommand
from core.enums import Register


class FakePrint(ContextAwareCommand):
    """
    Fake print command that does nothing.
    """

    command_id = 0x99
    expected_args = [
        Argument("register", Register, not_in_asm=True),
    ]

    def __init__(
        self,
        context: Context,
        register: bytes
    ):
        self.magic_number = 0x0
        super().__init__(context)
        self.add_argument("register", register) 

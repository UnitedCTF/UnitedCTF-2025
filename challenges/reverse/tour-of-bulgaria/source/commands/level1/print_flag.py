from typing import override

from core.objects.commands import ContextAwareCommand
from core.objects.context import Context


class PrintFlagCommand(ContextAwareCommand):
    """
    Print the flag.
    """

    command_id = 0x99
    expected_args = []

    def __init__(self, context: Context):
        super().__init__(context)

    @override
    def validate(self) -> bool:
        return True
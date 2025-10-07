from random import randint
from typing import cast, overload, override

from core.objects.commands import ContextAwareCommand
from core.objects.context import Context
from core.enums import Register
from core.objects.arguments import Argument


class LoopStartCommand(ContextAwareCommand):
    """
    Add a label to loop to.
    """

    command_id = 0xF
    expected_args = [
        Argument("id", int, not_in_asm=True),
        Argument("label", int, is_dynamic=True),
    ]

    def __init__(
        self,
        context: Context,
        id: bytes,
    ):
        super().__init__(context)
        self.add_argument("id", id)
        self.add_argument("label")
        self.add_label(
            self.get_argument("id").bytevalue, self.get_argument("label").bytevalue
        )

    @override
    def validate(self) -> bool:
        if not super().validate():
            return False

        arg = self.get_argument("id")
        if arg.value == -1:
            return False
        arg = self.get_argument("label")
        if arg.value == -1:
            return False
        return True


class SetLoopCounterCommand(ContextAwareCommand):
    """
    Set the loop counter.
    """

    command_id = 0xA
    expected_args = [
        Argument("value", int),
    ]

    def __init__(self, context: Context, value: bytes):
        super().__init__(context)
        self.add_argument("value", value)


class SetLoopCounterFromRegisterCommand(ContextAwareCommand):
    """
    Set the loop counter.
    """

    command_id = 0xAA
    expected_args = [
        Argument("value", Register),
    ]

    def __init__(self, context: Context, value: bytes):
        self.magic_number = 0xA
        super().__init__(context)
        self.add_argument("value", value)


class IterateLoopCommand(ContextAwareCommand):
    """
    Iterate the loop with the given id.
    """

    command_id = 0xE
    expected_args = [
        Argument("id", int, not_in_asm=True),
        Argument("label", int, is_dynamic=True),
    ]

    def __init__(
        self,
        context: Context,
        id: bytes,
    ):
        super().__init__(context)
        self.add_argument("id", id)
        self.add_argument("label", self.get_label(id))

    @override
    def validate(self) -> bool:
        if not super().validate():
            return False

        arg = self.get_argument("label")
        return arg.value != -1

from random import randint
from typing import cast, overload, override

from core.objects.commands import ContextAwareCommand
from core.objects.context import Context
from core.enums import Register, JumpCondition
from core.objects.arguments import Argument


class CreateJumpCommand(ContextAwareCommand):
    """
    Create a jump command with the given id.
    This command is used to create a jump command that can be used later.
    """

    command_id = 0x0
    expected_args = [
        Argument("id", int, not_in_asm=True),
        Argument("label", int, is_dynamic=True, not_in_asm=True),
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


class AddTrueLabelCommand(ContextAwareCommand):
    """
    Add a label to jump to if a condition is true.
    ! Important: You need to have called the CreateJumpCommand before this command. !
    """

    command_id = 0x7
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
        arg = self.get_argument("id")
        if arg.value == -1:
            return False
        arg = self.get_argument("label")
        if arg.value == -1:
            return False
        return True


class AddFalseLabelCommand(ContextAwareCommand):
    """
    Add a label to jump to if a condition is false.
    ! Important: You need to have called the CreateJumpCommand before this command. !
    """

    command_id = 0x8
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
        arg = self.get_argument("id")
        if arg.value == -1:
            return False
        arg = self.get_argument("label")
        if arg.value == -1:
            return False
        return True


class CompareRegisterCommand(ContextAwareCommand):
    """
    Jumps to a label depending on the comparison of two registers and a condition.
    """

    command_id = 0x9
    expected_args = [
        Argument("id", int, not_in_asm=True),
        Argument("label", int, is_dynamic=True),
        Argument("register_1", Register),
        Argument("register_2", Register),
        Argument("condition", JumpCondition),
    ]

    def __init__(
        self,
        context: Context,
        id: bytes,
        register_1: bytes,
        register_2: bytes,
        condition: bytes,
    ):
        super().__init__(context)
        self.add_argument("id", id)
        self.add_argument("label", self.get_label(id))
        self.add_argument("register_1", register_1)
        self.add_argument("register_2", register_2)
        self.add_argument("condition", condition)

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

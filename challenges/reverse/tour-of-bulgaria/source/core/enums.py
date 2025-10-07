from enum import Enum
from typing import override

class DynamicArgumentType(Enum):
    NONE = 0
    RANDOM = 1
    IN_CODE = 2

class RegisteredEnum(Enum):
    """
    Base class for all registered enums.
    """

    def __str__(self):
        return self.name.lower()

    @classmethod
    def is_valid(cls, int_value: int) -> bool:
        """
        Check if the given integer value is a valid .
        """
        return int_value in [values.value for values in cls.__members__.values()]

    @classmethod
    def get_children(cls):
        """
        Get all children of the enum.
        """
        return [child for child in cls.__subclasses__() if issubclass(child, cls)]

    def get_asm_value(self) -> str:
        """
        Convert an integer to a ResultRegisters enum.
        """
        if not self.is_valid(self.value):
            raise ValueError(f"Invalid asm value: {self.value}")
        return self.name.lower()


class JumpCondition(RegisteredEnum):
    EQUAL = 1
    NOT_EQUAL = 2
    GREATER = 3
    GREATER_OR_EQUAL = 4
    LESS = 5
    LESS_OR_EQUAL = 6

    @override
    def get_asm_value(self) -> str:
        """
        Convert an integer to a JumpCondition enum.
        """
        if not self.is_valid(self.value):
            raise ValueError(f"Invalid asm value: {self.value}")
        match self:
            case JumpCondition.EQUAL:
                return "je"
            case JumpCondition.NOT_EQUAL:
                return "jne"
            case JumpCondition.GREATER:
                return "jg"
            case JumpCondition.GREATER_OR_EQUAL:
                return "jge"
            case JumpCondition.LESS:
                return "jl"
            case JumpCondition.LESS_OR_EQUAL:
                return "jle"
        raise ValueError(f"Invalid asm value: {self.value}")


class Register(RegisteredEnum):
    RBX = 1
    R10 = 2
    R11 = 3
    R13 = 4
    R14 = 5
    R15 = 6

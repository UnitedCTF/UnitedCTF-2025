from abc import ABC, abstractmethod
from core.objects.arguments import ArgumentValueType, BigInt
from core.enums import RegisteredEnum


class ArgumentValidator(ABC):
    """
    A class to validate arguments based on their type.
    """

    @staticmethod
    def get_validator(value_type: ArgumentValueType):
        """
        Get the appropriate validator for the given value type.
        """
        if value_type == int:
            return IntValidator()
        elif value_type == BigInt:
            return BigIntValidator()
        elif value_type == str:
            return StringValidator()
        elif value_type == bytes:
            return BytesValidator()
        elif value_type in RegisteredEnum.get_children():
            return EnumValidator(value_type)
        return None

    @abstractmethod
    def validate(self, value) -> bool:
        """
        Validate the argument value.
        This method should be implemented by subclasses.
        """
        pass


class IntValidator(ArgumentValidator):
    """
    Validator for integer arguments.
    """

    def validate(self, value: int) -> bool:
        if not isinstance(value, int):
            raise ValueError(f"Expected int, got {type(value).__name__}")
        if value < 0 or value > 0xFFFF:
            raise ValueError(f"Integer argument out of range: {value}")
        return True


class BigIntValidator(ArgumentValidator):
    """
    Validator for BigInt arguments.
    """

    def validate(self, value: BigInt) -> bool:
        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"BigInt argument out of range: {value}")
        return True


class IntValidator(ArgumentValidator):
    """
    Validator for integer arguments.
    """

    def validate(self, value: int) -> bool:
        if not isinstance(value, int):
            raise ValueError(f"Expected int, got {type(value).__name__}")
        if value < 0 or value > 0xFFFF:
            raise ValueError(f"Integer argument out of range: {value}")
        return True


class StringValidator(ArgumentValidator):
    """
    Validator for string arguments.
    """

    def validate(self, value: str) -> bool:
        if not isinstance(value, str):
            raise ValueError(f"Expected str, got {type(value).__name__}")
        if len(value) > 255:
            raise ValueError(f"String argument too long: {value}")
        return True


class BytesValidator(ArgumentValidator):
    """
    Validator for bytes arguments.
    """

    def validate(self, value: bytes) -> bool:
        if not isinstance(value, bytes):
            raise ValueError(f"Expected bytes, got {type(value).__name__}")
        if len(value) > 255:
            raise ValueError(f"Bytes argument too long: {value}")
        return True


class EnumValidator(ArgumentValidator):
    """
    Validator for enum arguments.
    """

    def __init__(self, enum_type):
        self.enum_type = enum_type

    def validate(self, value) -> bool:
        if not isinstance(value, self.enum_type):
            raise ValueError(
                f"Expected {self.enum_type.__name__}, got {type(value).__name__}"
            )
        if not self.enum_type.is_valid(value.value):
            raise ValueError(f"Invalid enum argument: {value}")
        return True

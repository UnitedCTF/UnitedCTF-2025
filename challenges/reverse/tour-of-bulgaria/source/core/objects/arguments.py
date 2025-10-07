from dataclasses import dataclass
from core.objects.types import ArgumentValueType, BigInt
from core.objects.data_validator import ArgumentValidator
from core.enums import RegisteredEnum


@dataclass
class Argument:
    name: str
    value_type: type
    not_in_asm: bool = False
    is_dynamic: bool = False
    priority: int = 0

@dataclass
class CompiledArgument:
    name: str
    value_type: type
    value: ArgumentValueType
    subname: str = ""
    priority: int = 0
    bytevalue: bytes = b"\0"

    def __post_init__(self):
        if self.value_type == int or self.value_type == BigInt:
            self.bytevalue = self.value.to_bytes(2 if self.value_type == int else 8, "little")
        elif self.value_type == str:
            self.bytevalue = self.value.encode("utf-8")
        elif self.value_type == bytes:
            self.bytevalue = self.value
        elif self.value_type in RegisteredEnum.get_children():
            self.bytevalue = self.value.value.to_bytes(2, "little")
        
    def get_name(self) -> str:
        """
        Get the name of the argument, including subname if present.
        """
        return f"{self.name}_{self.subname}" if self.subname else self.name
    
    def validate(self) -> bool:
        validator = ArgumentValidator.get_validator(self.value_type)
        if validator is None:
            return True
        return validator.validate(self.value)
@dataclass
class CommandAttributes:
    expected_args: list[Argument]
    command: type
    name: str
    command_id: int = -1

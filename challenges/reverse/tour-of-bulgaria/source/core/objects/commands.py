from dataclasses import dataclass
from pathlib import Path
from random import randbytes

from core.objects.types import BigInt
from core.enums import RegisteredEnum
from core.objects.arguments import Argument, CommandAttributes, CompiledArgument
from core.objects.context import Context, ContextRegistered


@dataclass
class Command:
    command_id: int
    expected_args: list[Argument]
    asm_translation: str
    current_args: list[CompiledArgument]
    magic_number: int = -1

    def __init__(self):
        if self.magic_number == -1:
            self.magic_number = self.command_id
    
    @classmethod
    def get_attributes(cls) -> CommandAttributes:
        """
        Get the command attributes.
        """
        return CommandAttributes(
            expected_args=cls.expected_args,
            command=cls,
            name=cls.__name__,
            command_id=cls.command_id,
        )

    def get_current_args(self) -> list[CompiledArgument]:
        """
        Get the current arguments of the command sorted by priority. Higher priority arguments come first.
        """
        return sorted(self.current_args, key=lambda x: x.priority, reverse=True)

    def add_argument(self, name: str, value: bytes = None, id: bytes = 0):
        """
        Add an argument to the command.
        """
        expected = self.get_expected_argument(name)
        if expected is None:
            raise ValueError(f"Argument {name} not found in expected arguments")

        if expected.is_dynamic and value is None:
            value = (
                randbytes(8) if expected.value_type in (bytes, str) else randbytes(2)
            )
        if expected.value_type in [int, str, bytes, BigInt]:
            casted_value = value
            if expected.value_type == int or expected.value_type == BigInt:
                casted_value = int.from_bytes(value, "little")
            elif expected.value_type == str:
                casted_value = value.decode("utf-8")
            elif expected.value_type == bytes:
                casted_value = bytes(value)
        elif expected.value_type in RegisteredEnum.get_children():
            casted_value = expected.value_type(int.from_bytes(value, "little"))
        
        int_id = int.from_bytes(id, "little") if id else 0
        self.current_args.append(
            CompiledArgument(
                name,
                expected.value_type,
                casted_value,
                str(int_id) if id else "",
                expected.priority,
            )
        )

    def validate(self) -> bool:
        """
        Validate the command.
        """
        if len(self.current_args) != len(self.expected_args):
            print(f"Command {self.command_id} has {len(self.current_args)} arguments, expected {len(self.expected_args)}")
            return False
        for expected, current in zip(self.expected_args, self.current_args):
            if not self._is_valid(expected, current):
                return False

        return True

    def _is_valid(self, expected: Argument, current: CompiledArgument) -> bool:
        """
        Check if the current argument matches the expected argument.
        """
        if expected.name != current.name:
            print(f"Expected argument {expected.name}, got {current.name}")
            return False
        if expected.value_type != current.value_type:
            print(
                f"Expected argument type {expected.value_type}, got {current.value_type}"
            )
            return False
        try:
            current.validate()
        except ValueError as e:
            print(f"Argument validation failed: {e}")
            return False


        return True

    def get_argument(self, name: str) -> CompiledArgument | None:
        """
        Get an argument by name.
        """
        for arg in self.current_args:
            if arg.name == name:
                return arg
        return None

    def get_expected_argument(self, name: str) -> Argument | None:
        """
        Get an expected argument by name.
        """
        for arg in self.expected_args:
            if arg.name == name:
                return arg
        return None


@dataclass
class ContextAwareCommand(Command, ContextRegistered):
    _context: Context = None

    def __init__(self, context: Context):
        super().__init__()
        self._context = context
        self._load_command_asm()

    def _register_command(self):
        """
        Register the command in the context.
        """
        if self.command_id in self._context._registered_commands:
            raise ValueError(f"Command with id {self.command_id} already registered")
        self._context._registered_commands[self.command_id] = self.get_attributes()

    def _load_command_asm(self):
        """
        Load the command assembly file.
        """
        asm_file = self._get_command_asm_file()
        if not asm_file.exists():
            raise FileNotFoundError(f"Command assembly file not found: {asm_file}")
        with open(asm_file, "rb") as f:
            self.asm_translation = f.read().decode("utf-8")
        self.current_args = []

    def _get_command_asm_file(self) -> Path:
        """
        Get the command file path.
        """
        return Path(f"{self._context.command_asm_folder}/{hex(self.magic_number)}.asm")

    def add_label(self, id: bytes, label: bytes):
        """
        Add a label to the context.
        """
        if label in self._context.labels:
            raise ValueError(f"Label {label} already exists")
        self._context.labels[id] = label

    def get_label(self, id: bytes) -> bytes:
        """
        Get a label by id.
        """
        return self._context.labels[id] if id in self._context.labels else b"\0"

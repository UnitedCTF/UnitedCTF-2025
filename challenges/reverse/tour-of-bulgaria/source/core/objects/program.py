from dataclasses import dataclass
from pathlib import Path
from subprocess import PIPE, Popen
from typing import cast
from uuid import uuid4
from pwd import getpwnam
from os import setuid, setgid, remove

from core.objects.types import BigInt
from core.objects.data_validator import BigIntValidator, StringValidator, IntValidator, BytesValidator
from core.objects.commands import Command
from core.enums import RegisteredEnum


@dataclass
class ExecutionResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


@dataclass
class CompiledProgram:
    code: str
    _compiled: bool = False
    compiled_path: Path | None = None

    def compile(self) -> bool:
        """
        Compile the program.
        """
        if self._compiled:
            return False
        file_name = uuid4()
        asm_path = Path(f"/tmp/{file_name}.asm")
        obj_path = Path(f"/tmp/{file_name}.o")
        executable_path = Path(f"/tmp/{file_name}")
        with open(asm_path.absolute(), "w") as f:
            f.write(self.code)
        try:
            _, err = Popen(
                [
                    "nasm",
                    "-f",
                    "elf64",
                    "-o",
                    str(obj_path.absolute()),
                    str(asm_path.absolute()),
                ],
                stdout=PIPE,
                stderr=PIPE,
            ).communicate()
            if err:
                raise ValueError(f"Assembly error: {err.decode('utf-8')}")
            _, err = Popen(
                ["ld", "-o", str(executable_path.absolute()), str(obj_path.absolute())],
                stdout=PIPE,
                stderr=PIPE,
            ).communicate()
            if err:
                raise ValueError(f"Linking error: {err.decode('utf-8')}")
            self.compiled_path = executable_path
            self._compiled = True
        except Exception as e:
            print(f"Compilation error: {e}")
            return False
        finally:
            if asm_path.exists():
                remove(asm_path)
            if obj_path.exists():
                remove(obj_path)
        return True

    def run(self) -> ExecutionResult:
        """
        Run the compiled program.
        """
        if not self._compiled:
            raise ValueError("Program not compiled")
        if self.compiled_path is None:
            raise ValueError("Compiled path not set")

        username = "nobody"
        user_info = getpwnam(username)
        uid = user_info.pw_uid
        gid = user_info.pw_gid

        def demote():
            setgid(gid)
            setuid(uid)

        process = Popen(
            [str(self.compiled_path.absolute())],
            stdout=PIPE,
            stderr=PIPE,
            preexec_fn=demote,
        )
        stdout, stderr = process.communicate()
        return ExecutionResult(stdout, stderr, process.returncode)


@dataclass
class Program:
    commands: list[Command]

    def bytecode(self) -> bytes:
        """
        Generate the bytecode for the program.
        """
        bytecode = bytearray()
        for cmd in self.commands:
            if not cmd.validate():
                raise ValueError(f"Invalid command: {cmd}")
            args = cmd.current_args
            bytecode.append(cmd.command_id)
            for arg in args:
                if (
                    expected_arg := cmd.get_expected_argument(arg.name)
                ) is None or expected_arg.is_dynamic:
                    continue
                if arg.value_type is int:
                    value = cast(int, arg.value)
                    bytecode.append(2)
                    bytecode.extend(value.to_bytes(2, "little"))
                elif arg.value_type is BigInt:
                    value = cast(BigInt, arg.value)
                    bytecode.append(8)
                    bytecode.extend(value.to_bytes(8, "little"))
                elif arg.value_type is str:
                    value = cast(str, arg.value)
                    bytecode.append(len(value))
                    bytecode.extend(value.encode("utf-8"))
                elif arg.value_type is bytes:
                    value = cast(bytes, arg.value)
                    bytecode.append(len(value))
                    bytecode.extend(value)
                elif issubclass(arg.value_type, RegisteredEnum):
                    value = cast(RegisteredEnum, arg.value)
                    bytecode.append(2)
                    bytecode.extend(value.value.to_bytes(2, "little"))
        return bytes(bytecode)
    
    def _print(self):
        """
        Print the program in a human-readable format.
        """
        for cmd in self.commands:
            print(f"Command ID: {cmd.command_id}, Command Name: {cmd.__class__.__name__}")
            for arg in cmd.current_args:
                print(f"  Argument: {arg.get_name()}, Value: {arg.value}")
                
    def build(self) -> CompiledProgram:
        program = """
        BITS 64
        section .data
        ![data]!
        
        section .text
        global _start

        _start:
        ![text]!
        mov rax, 60     
        xor rdi, rdi    
        syscall
        """

        compiled_data = ""
        asm_code = ""
        for cmd in self.commands:
            if not cmd.validate():
                raise ValueError(f"Invalid command: {cmd}")
            args = cmd.get_current_args()
            asm_translation = cmd.asm_translation
            for arg in args:
                if (
                    expected_arg := cmd.get_expected_argument(arg.name)
                ) is None or expected_arg.not_in_asm:
                    continue
                if arg.value_type is int or arg.value_type is BigInt:
                    value = cast(int, arg.value)
                    if not self._validate_int_arg(value, arg.value_type is BigInt):
                        raise ValueError(f"Integer argument too large: {value}")
                    asm_translation = asm_translation.replace(
                        f"![{arg.get_name()}]!", str(value)
                    )
                elif arg.value_type is str:
                    value = cast(str, arg.value)
                    if not self._validate_str_arg(value):
                        raise ValueError(f"Invalid string argument: {value}")
                    compiled_data += f"{arg.get_name()} db {', '.join(f"0x{ord(c):02x}" for c in value)}, 0\n"
                    asm_translation = asm_translation.replace(
                        f"![{arg.get_name()}]!", arg.get_name()
                    )
                elif arg.value_type in RegisteredEnum.__subclasses__():
                    value = cast(RegisteredEnum, arg.value)
                    if not value.is_valid(value.value):
                        raise ValueError(f"Invalid enum argument: {value}")
                    asm_translation = asm_translation.replace(
                        f"![{arg.get_name()}]!", value.get_asm_value()
                    )
                elif arg.value_type is bytes:
                    value = cast(bytes, arg.value)
                    if not self._validate_bytes_arg(value):
                        raise ValueError(f"Invalid bytes argument: {value}")
                    byte_list: list[str] = []
                    for byte in value:
                        byte_list.append(f"0x{byte:02x}")
                    compiled_data += f"{arg.get_name()} db {', '.join(byte_list)}\n"
                    asm_translation = asm_translation.replace(
                        f"![{arg.get_name()}]!", arg.get_name()
                    )
            asm_code += asm_translation + "\n"
        program = program.replace("![data]!", compiled_data)
        program = program.replace("![text]!", asm_code)
        return CompiledProgram(program)

    def _validate_str_arg(self, str_value: str) -> bool:
        """
        Validate a string argument.
        """
        return StringValidator().validate(str_value)

    def _validate_int_arg(self, int_value: int, is_bigint: bool) -> bool:
        """
        Validate an integer argument.
        """
        if is_bigint:
            return BigIntValidator().validate(int_value)
        return IntValidator().validate(int_value)

    def _validate_bytes_arg(self, bytes_value: bytes) -> bool:
        """
        Validate a bytes argument.
        """
        return BytesValidator().validate(bytes_value)

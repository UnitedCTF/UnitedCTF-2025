from core.objects.commands import Command
from core.objects.context import Context


class InstructionParser:
    _context = None

    def __init__(self, context: Context):
        self._context = context

    def parse(self, bytecode: bytes) -> list[Command]:
        try:

            byte_list = list(bytecode)
            if len(byte_list) < 1 or len(byte_list) > 4096:
                raise ValueError("Bytecode length must be between 1 and 4096 bytes")
            commands = []
            while byte_list:
                command_id = byte_list.pop(0)
                cmd_attr = self._context.get_command_attributes(command_id)
                args = []
                for expected in cmd_attr.expected_args:
                    if expected.is_dynamic:
                        continue
                    if not byte_list:
                        raise ValueError(
                            f"Unexpected end of bytecode while reading arguments for command: {cmd_attr.name}\nExpected argument: {expected.name}"
                        )
                    arg_size = byte_list.pop(0)
                    arg_value = byte_list[:arg_size]
                    byte_list = byte_list[arg_size:]
                    args.append(bytes(arg_value))
                command = cmd_attr.command(self._context, *args)
                commands.append(command)
            return commands
        except ValueError as e:
            raise e
        except Exception as e:
            print(f"An unexpected error occurred while parsing bytecode")
            exit(1)

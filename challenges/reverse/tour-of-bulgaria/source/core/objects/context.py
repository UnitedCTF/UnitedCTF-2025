from dataclasses import dataclass
from pathlib import Path

from core.objects.arguments import CommandAttributes
import importlib
import pkgutil
class ContextRegistered:
    pass


@dataclass
class Context:
    command_asm_folder: Path
    labels: dict[bytes, bytes] = None
    _registered_commands: dict[int, CommandAttributes] = None

    def __post_init__(self):
        if self.labels is None:
            self.labels = {}
        if self._registered_commands is None:
            self._registered_commands = {}
        if not isinstance(self.command_asm_folder, Path):
            raise ValueError("command_asm_folder must be a Path object")
        if not self.command_asm_folder.exists():
            raise FileNotFoundError(
                f"Command asm folder does not exist: {self.command_asm_folder}"
            )

        self._register_commands()

    def _register_commands(self):
        from core.objects.commands import ContextAwareCommand
        _import_all_subclasses("commands")
        commands = ContextAwareCommand.__subclasses__()
        for cmd in commands:
            if not hasattr(cmd, "get_attributes") or not callable(
                getattr(cmd, "get_attributes")
            ):
                continue
            attr = cmd.get_attributes()
            if attr.command_id in self._registered_commands:
                raise ValueError(f"Command ID {attr.command_id} already registered")
            self._registered_commands[attr.command_id] = attr
  
    
    def get_command_attributes(self, command_id: int) -> CommandAttributes:
        """
        Get the command attributes by command ID.
        """
        if command_id not in self._registered_commands:
            raise ValueError(f"Command ID {command_id} not registered")
        return self._registered_commands[command_id]

      
def _import_all_subclasses(package_name):
    package = importlib.import_module(package_name)

    for _, modname, ispkg in pkgutil.walk_packages(package.__path__, package_name + '.'):
        if not ispkg:
            importlib.import_module(modname)


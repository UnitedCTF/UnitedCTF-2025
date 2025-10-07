from pathlib import Path

import os
from core.objects.context import Context
from core.instruction_parser import InstructionParser
from core.objects.program import Program

DEBUG = os.environ.get("DEBUG", "0") == "1"

ctx = Context(command_asm_folder=Path(os.environ.get("COMMAND_ASM_FOLDER", "/asm")))
parser = InstructionParser(ctx)

def main_loop():
    program_hex = input("Send the program as a hex string: ")
    try:
        program_bytes = bytes.fromhex(program_hex.strip())
    except ValueError:
        print("Invalid hex string")
        return
        
    try:
        commands = parser.parse(program_bytes)
    except ValueError as e:
        print(f"\nError parsing bytecode: {e}\n")
        return
    if len(commands) == 0:
        print("No commands found in the program.")
        return

    program = Program(commands)
    if DEBUG:
        print()
        print("------- PROGRAM DUMP -------")
        program._print()
        print("------- END OF DUMP -------")
        print()
        
    compiled = program.build()
    if compiled.compile() is False:
        print("Compilation failed.")
        return


    result = compiled.run()
    print("Program executed")
    print()
    print("------- EXECUTION RESULT -------")
    if result.stderr:
        print("Error output:\n")
        print(result.stderr.decode('latin-1'))
        print()
    if result.stdout:
        print("Output:\n")
        print(result.stdout.decode('latin-1'))
        print()
    else:
        print()
        print("No output.")
        print()
    if result.exit_code != 0:
        print(f"Program exited with code {result.exit_code}")
    print("------- END OF RESULT -------")
    print()
if __name__ == "__main__":
    while True:
        main_loop()
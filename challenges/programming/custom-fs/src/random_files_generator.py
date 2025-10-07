import random
from tree import InodeType, Node

class RandomFilesGenerator:
    root_node: Node
    all_files: list[Node]
    all_directories: list[Node]

    def __init__(self) -> None:
        self.root_node = Node(name="/", type=InodeType.DIRECTORY)
        self.all_files = []
        self.all_directories = [self.root_node]

        self.generate_random_directory(self.root_node)

    def generate_number_from_tuple(self, t: tuple[int,int]) -> int:
        if t[0] == t[1]:
            return t[0]
        return random.randint(t[0], t[1])

    def generate_random_directory(self, node: Node, depth: tuple[int,int] = (3, 3), num_files: tuple[int,int] = (10, 12), num_dirs: tuple[int,int] = (5, 6)):
        chosen_depth = self.generate_number_from_tuple(depth)
        chosen_num_files = self.generate_number_from_tuple(num_files)
        chosen_num_dirs = self.generate_number_from_tuple(num_dirs)

        if chosen_depth == 0:
            return

        if chosen_depth == 1:
            for i in range(chosen_num_files):
                self.generate_random_file(node, f"file_{i}.bin")

        for i in range(chosen_num_dirs):
            new_node = Node(
                name=f"dir_{i}",
                type=InodeType.DIRECTORY
            )

            self.generate_random_directory(new_node, (chosen_depth - 1, chosen_depth - 1), num_files)
            node.add_child(new_node)
            self.all_directories.append(new_node)

    def generate_random_file(self, parent: Node, file_name: str, size: tuple[int,int] = (1, 1024)):
        chosen_size = self.generate_number_from_tuple(size)

        child = Node(
            name=file_name,
            type=InodeType.FILE,
            data=random.randbytes(chosen_size)
        )
        parent.add_child(child)
        self.all_files.append(child)

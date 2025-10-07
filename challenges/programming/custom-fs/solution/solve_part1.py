# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests",
# ]
# ///
import hashlib

import requests

from solve_common import read_inode
from tree import Inode


URL = "http://localhost:8000"


def main():
    current_challenge = requests.post(f"{URL}/challenge").json()
    for _ in range(10):
        print(current_challenge)

        disk_image_url = current_challenge["disk_image_url"]
        data = requests.get(f"{URL}{disk_image_url}", allow_redirects=True).content

        # Assuming the root inode is at cluster index 0
        root_inode = read_inode(data, 0)

        # You can now traverse the inode tree starting from root_inode
        # For example, to print all file names:
        def print_inode_tree(inode: Inode, depth: int = 0):
            print("  " * depth + f"{inode.name} ({inode.type.name})")
            if inode.first_child:
                print_inode_tree(inode.first_child, depth + 1)
            if inode.next_sibling:
                print_inode_tree(inode.next_sibling, depth)

        # print_inode_tree(root_inode)

        child = root_inode.find_path(current_challenge["wanted_file_path"])
        assert child is not None, "Child not found"

        checksum = hashlib.sha256(child.data).hexdigest()

        current_challenge = requests.post(
            "http://localhost:8000/challenge/solve",
            json={"uuid": current_challenge["uuid"], "file_sha256": checksum},
        ).json()

    print("Solved all challenges!")
    print(current_challenge)


if __name__ == "__main__":
    main()

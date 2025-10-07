# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests",
# ]
# ///
import base64
from pathlib import Path

import requests

from solve_common import read_inode
from tree import Inode, InodeType


URL = "http://localhost:8000"


def main():
    current_challenge = requests.post(f"{URL}/challenge").json()
    for _ in range(10):
        print(current_challenge)

        disk_image_url = current_challenge["disk_image_url"]
        data = requests.get(f"{URL}{disk_image_url}", allow_redirects=True).content

        # Assuming the root inode is at cluster index 0
        root_inode = read_inode(data, 0)

        file_path = Path(current_challenge["wanted_new_file_path"])
        dir_path = file_path.parent.as_posix()

        dir_inode = root_inode.find_path(dir_path)
        assert dir_inode is not None, "Parent directory not found"

        old_first_child = dir_inode.first_child
        dir_inode.first_child = Inode(
            name=file_path.name, type=InodeType.FILE, data=current_challenge["wanted_new_file_content"].encode()
        )

        dir_inode.first_child.next_sibling = old_first_child

        disk_image = root_inode.create_disk_image()

        current_challenge = requests.post(
            "http://localhost:8000/challenge/solve",
            json={"uuid": current_challenge["uuid"], "disk_image_base64": (base64.b64encode(disk_image)).decode()},
        ).json()

    print("Solved all challenges!")
    print(current_challenge)


if __name__ == "__main__":
    main()

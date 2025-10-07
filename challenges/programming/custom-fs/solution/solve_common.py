from tree import (
    CLUSTER_SIZE,
    FILE_SIZE,
    FIRST_CHILD_SIZE,
    HEADER_SIZE,
    NAME_SIZE,
    NEXT_SIBLING_SIZE,
    TYPE_SIZE,
    Inode,
    InodeType,
)


def read_inode(data: bytes, cluster_idx: int = 0) -> Inode:
    begin_offset = cluster_idx * CLUSTER_SIZE
    header = data[begin_offset : begin_offset + HEADER_SIZE]

    current_offset = 0

    name = header[current_offset : current_offset + NAME_SIZE].decode().split("\x00")[0]
    current_offset += NAME_SIZE

    type = int.from_bytes(header[current_offset : current_offset + TYPE_SIZE], "little")
    current_offset += TYPE_SIZE

    next_sibling = int.from_bytes(
        header[current_offset : current_offset + NEXT_SIBLING_SIZE], "little"
    )
    current_offset += NEXT_SIBLING_SIZE

    first_child = int.from_bytes(
        header[current_offset : current_offset + FIRST_CHILD_SIZE], "little"
    )
    current_offset += FIRST_CHILD_SIZE

    file_size_bytes = int.from_bytes(
        header[current_offset : current_offset + FILE_SIZE], "little"
    )

    if type == InodeType.FILE.value:
        file_data = data[
            begin_offset + HEADER_SIZE : begin_offset + HEADER_SIZE + file_size_bytes
        ]

    next_sibling_inode = read_inode(data, next_sibling) if next_sibling else None
    first_child_inode = read_inode(data, first_child) if first_child else None

    return Inode(
        name=name,
        type=InodeType(type),
        next_sibling=next_sibling_inode,
        first_child=first_child_inode,
        data=file_data if type == InodeType.FILE.value else b"",
    )

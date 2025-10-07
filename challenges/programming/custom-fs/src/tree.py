from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from functools import cached_property
import logging
from math import ceil


CLUSTER_SIZE = 512

"""
Name: 64 bytes (ends with null byte, must be at least 1 byte)
Type: 1 byte
Next Sibling: 4 bytes (cluster number)
First Child: 4 bytes (cluster number, only for directories)
File size: 4 bytes (only for files)
"""
NAME_SIZE = 64
TYPE_SIZE = 1
NEXT_SIBLING_SIZE = 4
FIRST_CHILD_SIZE = 4
FILE_SIZE = 4
HEADER_SIZE = NAME_SIZE + TYPE_SIZE + NEXT_SIBLING_SIZE + FIRST_CHILD_SIZE + FILE_SIZE # 77 bytes
DATA_IN_FIRST_CLUSTER = CLUSTER_SIZE - HEADER_SIZE # 435 bytes


class InodeType(IntEnum):
    FILE = 0
    DIRECTORY = 1


@dataclass
class Inode:
    name: str
    type: InodeType
    next_sibling: Inode | None = None
    first_child: Inode | None = None
    data: bytes = b""
    cluster_idx: int | None = None

    @cached_property
    def clusters_count(self) -> int:
        logging.debug(f"[{self.name}] Calculating clusters count: {self.type} (data length: {len(self.data)})")
        if self.type == InodeType.DIRECTORY or len(self.data) <= DATA_IN_FIRST_CLUSTER:
            return 1
        return 1 + ceil((len(self.data) - DATA_IN_FIRST_CLUSTER) / CLUSTER_SIZE)

    def _set_cluster_idx(self, last_assigned_idx: int = -1) -> int:
        logging.debug(f"[{self.name}] Setting cluster index: {last_assigned_idx + 1} (type: {self.type})")

        self.cluster_idx = last_assigned_idx + 1
        last_assigned_idx += self.clusters_count
        if self.first_child:
            last_assigned_idx = self.first_child._set_cluster_idx(last_assigned_idx)
        if self.next_sibling:
            last_assigned_idx = self.next_sibling._set_cluster_idx(last_assigned_idx)

        return last_assigned_idx

    def _to_bytes(self, current_bytes: bytes = b"") -> bytes:
        logging.debug(f"[{self.name}] Converting to bytes")

        assert self.cluster_idx is not None, f"[{self.name}] Cluster index must be set before converting to bytes"
        assert len(current_bytes) == self.cluster_idx * CLUSTER_SIZE, f"[{self.name}] Current bytes length mismatch: got {len(current_bytes)}, expected {self.cluster_idx * CLUSTER_SIZE}"

        name_bytes = self.name.encode()[:(NAME_SIZE - 1)].ljust(NAME_SIZE, b'\x00')
        type_byte = self.type.value.to_bytes(TYPE_SIZE, 'little').ljust(TYPE_SIZE, b'\x00')
        next_sibling_bytes = ((self.next_sibling.cluster_idx if self.next_sibling else None) or 0).to_bytes(NEXT_SIBLING_SIZE, 'little').ljust(NEXT_SIBLING_SIZE, b'\x00')
        first_child_bytes = ((self.first_child.cluster_idx if self.first_child else None) or 0).to_bytes(FIRST_CHILD_SIZE, 'little').ljust(FIRST_CHILD_SIZE, b'\x00')
        file_size_bytes = len(self.data).to_bytes(FILE_SIZE, 'little').ljust(FILE_SIZE, b'\x00') if self.type == InodeType.FILE else b'\x00' * FILE_SIZE
        header = name_bytes + type_byte + next_sibling_bytes + first_child_bytes + file_size_bytes
        assert len(header) == HEADER_SIZE, f"[{self.name}] Header size mismatch: got {len(header)}, expected {HEADER_SIZE}"

        if self.type == InodeType.DIRECTORY:
            current_bytes += header + (b'\x00' * (CLUSTER_SIZE - HEADER_SIZE))
        elif self.type == InodeType.FILE:
            first_cluster_data = self.data[:DATA_IN_FIRST_CLUSTER].ljust(DATA_IN_FIRST_CLUSTER, b'\x00')
            other_clusters_data = self.data[DATA_IN_FIRST_CLUSTER:].ljust(CLUSTER_SIZE * (self.clusters_count - 1), b'\x00')
            current_bytes += header + first_cluster_data + other_clusters_data

        assert len(current_bytes) == (self.cluster_idx + self.clusters_count) * CLUSTER_SIZE, f"[{self.name}] Current bytes length mismatch after writing: got {len(current_bytes)}, expected {(self.cluster_idx + 1) * CLUSTER_SIZE}"

        logging.debug(f"[{self.name}] Current bytes length: {len(current_bytes)}, my cluster index: {self.cluster_idx}, my cluster count: {self.clusters_count}")

        if self.first_child:
            current_bytes = self.first_child._to_bytes(current_bytes)
        if self.next_sibling:
            current_bytes = self.next_sibling._to_bytes(current_bytes)

        return current_bytes

    def create_disk_image(self) -> bytes:
        self._set_cluster_idx()
        return self._to_bytes()

    def find_child(self, name: str, siblings: bool = False) -> Inode | None:
        if siblings:
            if self.name == name:
                return self
            if self.next_sibling:
                return self.next_sibling.find_child(name, siblings=True)
            return None

        elif self.first_child:
            return self.first_child.find_child(name, siblings=True)

        return None

    def find_path(self, path: str) -> Inode | None:
        parts = path.split("/")
        current_inode = self
        for part in parts:
            if part == "":
                continue
            current_inode = current_inode.find_child(part)
            if current_inode is None:
                return None

        return current_inode

@dataclass
class Node:
    name: str
    type: InodeType
    children: list[Node] = field(default_factory=list)
    parent: Node | None = field(default=None, repr=False)
    data: bytes = field(default=b"", repr=False)

    def add_child(self, child_node: Node):
        self.children.append(child_node)
        child_node.parent = self

    def to_inode(self) -> Inode:
        inode = Inode(name=self.name, type=self.type, data=self.data)

        current_child: Inode | None = None
        for child in self.children:
            if current_child is None:
                current_child = child.to_inode()
                inode.first_child = current_child
            else:
                current_child.next_sibling = child.to_inode()
                current_child = current_child.next_sibling

        return inode

    def __str__(self, level=0) -> str:
        ret = "\t" * level + repr(self.name) + (" (DIR)" if self.type == InodeType.DIRECTORY else " (FILE)") + "\n"
        for child in self.children:
            ret += child.__str__(level + 1)
        return ret

    @property
    def full_path(self) -> str:
        if self.parent is None:
            return self.name
        parent_path = self.parent.full_path
        if parent_path == "/":
            return f"/{self.name}"
        return f"{parent_path}/{self.name}"

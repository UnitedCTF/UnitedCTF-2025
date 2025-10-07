from __future__ import annotations

import base64
from dataclasses import dataclass, field
import datetime
from pathlib import Path
import random
import string
from typing import ClassVar
import uuid

from pydantic import BaseModel
from random_files_generator import RandomFilesGenerator
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from solve_common import read_inode

app = FastAPI()

Path("files").mkdir(exist_ok=True)
app.mount("/files", StaticFiles(directory="files"), name="files")

FLAG = "flag-9031f35cd842df12"
TIMEOUT = 5  # seconds
REQUIRED_SOLVE_COUNT = 10


class ChallengeCreateReponse(BaseModel):
    uuid: str
    disk_image_url: str
    wanted_new_file_path: str
    wanted_new_file_content: str


class ChallengeSolvedResponse(BaseModel):
    message: str


class ChallengeSolveRequest(BaseModel):
    uuid: str
    disk_image_base64: str


@dataclass
class Challenge:
    uuid: str = field(default_factory=lambda: uuid.uuid4().hex)
    disk_image_path: Path = field(init=False)
    wanted_new_file_path: str = field(init=False)
    wanted_new_file_content: str = field(init=False)
    created_at: datetime.datetime = field(init=False)
    all_files: list[str] = field(init=False)
    challenge_count: int = 1

    all_challenges: ClassVar[dict[str, Challenge]] = {}

    def __post_init__(self):
        generator = RandomFilesGenerator()
        self.disk_image_path = Path(f"files/disk-{self.uuid}.img")
        random_dir = random.choice(generator.all_directories)
        self.wanted_new_file_path = f"{random_dir.full_path}/new_file_{self.uuid}.txt"
        self.wanted_new_file_content = "".join(
            random.choices(
                string.ascii_letters + string.digits, k=random.randint(1000, 2000)
            )
        )

        disk_image = generator.root_node.to_inode().create_disk_image()
        with open(self.disk_image_path, "wb") as f:
            f.write(disk_image)

        self.created_at = datetime.datetime.now()

        self.all_files = [node.full_path for node in generator.all_files]

        Challenge.all_challenges[self.uuid] = self

    def __del__(self):
        try:
            self.disk_image_path.unlink()
        except FileNotFoundError:
            pass

    def as_challenge_response(self) -> ChallengeCreateReponse:
        return ChallengeCreateReponse(
            uuid=self.uuid,
            disk_image_url="/" + self.disk_image_path.as_posix(),
            wanted_new_file_path=self.wanted_new_file_path,
            wanted_new_file_content=self.wanted_new_file_content,
        )

    @staticmethod
    def get(uuid: str) -> Challenge:
        challenge = Challenge.all_challenges.get(uuid)
        if challenge is None:
            raise HTTPException(status_code=404, detail="Challenge not found")

        return challenge

    def integrity_check(self, original_disk_image: bytes, new_disk_image: bytes) -> None:
        # Check that no other files were modified
        try:
            original_inode = read_inode(original_disk_image)
            new_inode = read_inode(new_disk_image)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error while reading the provided disk image: {e}",
            ) from e

        for file_path in self.all_files:
            original_file_inode = original_inode.find_path(file_path)
            new_file_inode = new_inode.find_path(file_path)

            if original_file_inode is None or new_file_inode is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"File {file_path} not found in the provided disk image",
                )

            if original_file_inode.type != new_file_inode.type:
                raise HTTPException(
                    status_code=400,
                    detail=f"File {file_path} type has been modified",
                )

            if original_file_inode.data != new_file_inode.data:
                raise HTTPException(
                    status_code=400,
                    detail=f"File {file_path} content has been modified",
                )

    def check_solution(self, disk_image: bytes) -> None:
        if (
            self.created_at + datetime.timedelta(seconds=TIMEOUT)
            < datetime.datetime.now()
        ):
            raise HTTPException(status_code=400, detail="Too slow! Try again")

        self.integrity_check(
            original_disk_image=self.disk_image_path.read_bytes(),
            new_disk_image=disk_image,
        )

        try:
            inode = read_inode(disk_image)
            new_file_inode = inode.find_path(self.wanted_new_file_path)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error while reading the provided disk image: {e}",
            ) from e

        if new_file_inode is None:
            raise HTTPException(
                status_code=400,
                detail=f"File {self.wanted_new_file_path} not found in the provided disk image",
            )

        if new_file_inode.type != new_file_inode.type.FILE:
            raise HTTPException(
                status_code=400,
                detail=f"{self.wanted_new_file_path} is not a file",
            )

        if new_file_inode.data != self.wanted_new_file_content.encode():
            raise HTTPException(
                status_code=400,
                detail="File content does not match the expected content",
            )

    def process_solve(
        self, disk_image: bytes
    ) -> ChallengeSolvedResponse | ChallengeCreateReponse:
        try:
            self.check_solution(disk_image)
            if self.challenge_count == REQUIRED_SOLVE_COUNT:
                return ChallengeSolvedResponse(
                    message=f"Congratulations! Here is your flag: {FLAG}"
                )
            else:
                return Challenge(
                    challenge_count=self.challenge_count + 1
                ).as_challenge_response()
        finally:
            self.remove()

    def remove(self):
        Challenge.all_challenges.pop(self.uuid)


@app.post("/challenge")
def create_challenge() -> ChallengeCreateReponse:
    return Challenge().as_challenge_response()


@app.post("/challenge/solve")
def solve(
    request: ChallengeSolveRequest,
) -> ChallengeSolvedResponse | ChallengeCreateReponse:
    try:
        disk_image = base64.b64decode(request.disk_image_base64)
        return Challenge.get(request.uuid).process_solve(disk_image)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64: {e}") from e

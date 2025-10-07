from __future__ import annotations

from dataclasses import dataclass, field
import datetime
import hashlib
from pathlib import Path
import random
from typing import ClassVar
import uuid

from pydantic import BaseModel
from random_files_generator import RandomFilesGenerator
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from tree import Node

app = FastAPI()

Path("files").mkdir(exist_ok=True)
app.mount("/files", StaticFiles(directory="files"), name="files")

FLAG = "flag-b9725e4030930a93"
TIMEOUT = 5  # seconds
REQUIRED_SOLVE_COUNT = 10


class ChallengeCreateReponse(BaseModel):
    uuid: str
    disk_image_url: str
    wanted_file_path: str

class ChallengeSolvedResponse(BaseModel):
    message: str


class ChallengeSolveRequest(BaseModel):
    uuid: str
    file_sha256: str


@dataclass
class Challenge:
    uuid: str = field(default_factory=lambda: uuid.uuid4().hex)
    disk_image_path: Path = field(init=False)
    random_file: Node = field(init=False)
    created_at: datetime.datetime = field(init=False)
    challenge_count: int = 1

    all_challenges: ClassVar[dict[str, Challenge]] = {}

    def __post_init__(self):
        generator = RandomFilesGenerator()
        self.disk_image_path = Path(f"files/disk-{self.uuid}.img")
        self.random_file = random.choice(generator.all_files)

        disk_image = generator.root_node.to_inode().create_disk_image()
        with open(self.disk_image_path, "wb") as f:
            f.write(disk_image)

        self.created_at = datetime.datetime.now()

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
            wanted_file_path=self.random_file.full_path,
        )

    @staticmethod
    def get(uuid: str) -> Challenge:
        challenge = Challenge.all_challenges.get(uuid)
        if challenge is None:
            raise HTTPException(status_code=404, detail="Challenge not found")

        return challenge

    def check_solution(self, file_checksum: str) -> None:
        if self.created_at + datetime.timedelta(seconds=TIMEOUT) < datetime.datetime.now():
            raise HTTPException(status_code=400, detail="Too slow! Try again")

        expected_checksum = hashlib.sha256(self.random_file.data).hexdigest()
        if file_checksum != expected_checksum:
            raise HTTPException(
                status_code=400, detail=f"Wrong checksum! Expected {expected_checksum}"
            )

    def process_solve(self, file_checksum: str) -> ChallengeSolvedResponse | ChallengeCreateReponse:
        try:
            self.check_solution(file_checksum)
            if self.challenge_count == REQUIRED_SOLVE_COUNT:
                return ChallengeSolvedResponse(message=f"Congratulations! Here is your flag: {FLAG}")
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
def solve(request: ChallengeSolveRequest) -> ChallengeSolvedResponse | ChallengeCreateReponse:
    return Challenge.get(request.uuid).process_solve(request.file_sha256)

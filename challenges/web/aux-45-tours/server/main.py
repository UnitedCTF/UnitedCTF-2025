import io
import pathlib
from typing import Annotated
from fastapi import FastAPI, File, UploadFile
import subprocess
import uuid
import os

from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

TEMPORARY_FILE_DIR = pathlib.Path('workdir').resolve()
MAX_UPLOAD_SIZE = 1024 * 1024 * 32 # 32mb
ALLOWED_EXTENSIONS = {'.flac', '.wav', '.mp3', '.m4a', '.wma', '.ogg'}

api = FastAPI()

app = FastAPI()
app.mount('/api', api)
app.mount('/', StaticFiles(directory='static', html=True))

@api.post("/convert")
async def convert(file: Annotated[UploadFile, File()]):
    if file.size > MAX_UPLOAD_SIZE:
        return JSONResponse(content={'error': 'file too large'}, status_code=400)

    filename: str = os.path.basename(file.filename)
    if os.path.splitext(filename)[1] not in ALLOWED_EXTENSIONS:
        return JSONResponse(content={'error': 'unsupported file extension'}, status_code=400)

    try:
        input_path = TEMPORARY_FILE_DIR.joinpath(filename)
        with open(input_path, 'wb') as f:
            f.write(file.file.read())

        output_path = TEMPORARY_FILE_DIR.joinpath(f'{uuid.uuid4()}.flac')

        print(f'converting to flac: {input_path} -> {output_path}')
        proc = subprocess.run(
            ['/usr/bin/ffmpeg', '-protocol_whitelist', 'file,concat', '-i', file.filename, output_path],
            cwd=TEMPORARY_FILE_DIR,
            timeout=10
        )
        assert proc.returncode == 0

        with open(output_path, 'rb') as f:
            output_data = f.read()

        return StreamingResponse(io.BytesIO(output_data), media_type='audio/flac', headers={
            'Content-Disposition': f'attachment; filename={filename}.flac'
        })
    finally:
        try:
            os.remove(input_path)
            os.remove(output_path)
        except FileNotFoundError:
            pass
FROM python:3.11-slim

WORKDIR /app


COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt


COPY make_db.py .

RUN python3 ./make_db.py


COPY server.py .

EXPOSE 8080

CMD ["python3", "server.py"]

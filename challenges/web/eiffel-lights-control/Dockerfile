FROM python:3.13-slim
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pip install --upgrade pip && pip install flask requests

ENV FLASK_ENV=development
EXPOSE 5000
LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

CMD ["sh", "-c", "python app/clock.py & flask --app app/main.py run --host=0.0.0.0 --port=5000"]

FROM python:3.13-alpine

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025
EXPOSE 8000
WORKDIR /app

RUN apk add ffmpeg curl

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN echo "flag-M3rc1Fabr1c3B3ll4rd0f8b2e15" > /flag.txt

ADD --chmod=700 health /health

RUN mkdir workdir
ADD static static/
COPY main.py .

CMD ["fastapi", "run", "/app/main.py"]
HEALTHCHECK --interval=1m CMD /health/check.sh

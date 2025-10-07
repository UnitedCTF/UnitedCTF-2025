FROM python:3.13-slim

WORKDIR /app

RUN pip install flask ldap3

COPY app.py .

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]

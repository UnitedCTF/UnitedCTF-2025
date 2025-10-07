FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8


RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server ca-certificates sudo cron \
 && rm -rf /var/lib/apt/lists/*


RUN useradd -m -s /bin/bash boualem 


RUN mkdir -p /var/run/sshd \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config


WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN echo "flag-d1sc0_m4ghreb_f0r3v3r-5k2TT5iz" > /flag.txt \
 && chmod 770 /flag.txt

COPY songs-lyrics songs-lyrics/
COPY health-check-disco-maghreb.py .
COPY server.py .

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 771 /usr/local/bin/entrypoint.sh

EXPOSE 22 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

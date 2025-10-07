# Use a base image
FROM debian:12.5-slim

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

# Install SSH server and other necessary packages
RUN apt update && apt install -y \
    openssh-server \
    vim \
    nano \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Create SSH directory and configure SSH
RUN mkdir /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create a new user for the challenge
RUN useradd -m -s /bin/bash -d /home/ctfuser ctfuser
# Set password for ctfuser (change this for production)
RUN echo 'ctfuser:longleat2025' | chpasswd

# Set the working directory to the user's home directory
WORKDIR /home/ctfuser

# Add your challenge directory inside the user's home
COPY createchallenge.py createchallenge.py
RUN python3 createchallenge.py
RUN rm createchallenge.py

# Remove specific command binaries to make it more challenging
RUN rm -f /bin/find /bin/grep /bin/fgrep /bin/*grep* /bin/cat

# Set ownership of files to ctfuser
RUN chown -R ctfuser:ctfuser /home/ctfuser

# Expose SSH port
EXPOSE 22

# Start SSH service
CMD ["/usr/sbin/sshd", "-D"]

FROM maven:3.8.6-openjdk-11-slim

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

# Install necessary packages
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    nano \
    gcc \
    make \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create users
RUN useradd -m -s /bin/bash localuser
RUN useradd -m -s /bin/bash www-data || true

# Set up directory structure
WORKDIR /opt/horloger

# Copy Maven project files first for better layer caching
COPY web/pom.xml ./web/
COPY web/src ./web/src

# Copy other components
COPY privesc/ ./privesc/
COPY setup/ ./setup/
COPY flags/ ./flags/

# Make setup script executable
RUN chmod +x ./setup/setup.sh

# Build and setup privilege escalation binary
RUN cd privesc && gcc -o timedatectl timedatectl.c
RUN cp privesc/timedatectl /usr/local/bin/timedatectl
RUN chown root:root /usr/local/bin/timedatectl
RUN chmod 4755 /usr/local/bin/timedatectl

# Set up flags - user flag accessible to www-data, root flag only to root
RUN cp flags/user.txt /opt/horloger/web/user.txt
RUN chown www-data:www-data /opt/horloger/web/user.txt
RUN chmod 600 /opt/horloger/web/user.txt

RUN cp flags/root.txt /root/root.txt
RUN chown root:root /root/root.txt
RUN chmod 600 /root/root.txt

# Build web application with Maven
RUN cd web && mvn clean package -DskipTests

# Run setup script to configure system (must run as root)
RUN ./setup/setup.sh

# Clean up sensitive build files and setup materials after setup
RUN rm -rf /opt/horloger/privesc
RUN rm -rf /opt/horloger/flags
RUN rm -rf /opt/horloger/setup
RUN rm -rf /opt/horloger/web/src
RUN rm -rf /opt/horloger/web/target/classes
RUN rm -rf /opt/horloger/web/pom.xml

# Set final permissions - webapp files owned by www-data
RUN chown -R www-data:www-data /opt/horloger/web

# Create startup script that switches to www-data user
RUN echo '#!/bin/bash\nsu -s /bin/bash www-data -c "cd /opt/horloger/web && java -Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true -jar target/horloger-*.jar"' > /start.sh
RUN chmod +x /start.sh

# Expose port
EXPOSE 8080

# Run as www-data user
CMD ["/start.sh"]

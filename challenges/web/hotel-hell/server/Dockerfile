FROM node:24-alpine

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

RUN apk add --no-cache ripgrep

WORKDIR /srv

COPY init/*.sh ./
RUN chmod +x *.sh && ./*.sh && rm *.sh

RUN echo "flag-0cdc46e7fc1fee49" > /flag.txt

COPY package*.json ./
RUN npm install

COPY main.js random.js template.cfg ./
ADD public public/

EXPOSE 3000

ENTRYPOINT [ "node", "/srv/main.js" ]

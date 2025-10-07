FROM gcc:15 AS builder

WORKDIR /build

ADD scripts/ .

RUN gcc printflag1.c -o printflag1
RUN gcc printflag2.c -o printflag2


FROM mediawiki:1.44.0

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

COPY --from=builder /build/printflag1 /build/printflag2 /
RUN chmod 111 /printflag*

WORKDIR /var/www/

COPY rest.php.diff .
RUN patch html/rest.php < rest.php.diff
RUN rm rest.php.diff

ADD --chown=www-data:www-data data/ data/
ADD --chown=www-data:www-data images/ html/images/
COPY --chown=www-data:www-data LocalSettings.php checkflag1.php html/
COPY --chown=www-data:www-data logo.png html/resources/assets/

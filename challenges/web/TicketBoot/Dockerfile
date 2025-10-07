FROM gradle:8.4.0-jdk17-alpine AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build --no-daemon

FROM eclipse-temurin:17-alpine
RUN mkdir /app
COPY --from=build /home/gradle/src/build/libs/*.jar /app/TicketBoot.jar

RUN mkdir -p /app/classes /app/resources /app/libs
COPY --from=build /home/gradle/src/build/classes/java/main/ /app/classes/
COPY --from=build /home/gradle/src/build/resources/main/ /app/resources/
COPY --from=build /home/gradle/src/build/dependencies/ /app/libs/
COPY flag3.txt /flag3.txt

WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

EXPOSE 8080

ENV \
    ticketboot.firstFlag="flag-w3lc0m3_t0_th3_t1ck3t_b00t_e058b670" \
    ticketboot.secondFlag="flag-c0ngr4tul4t10ns_h3r3_1s_y0ur_cru1s3_t1ck3t!!_feccc248" \
    ticketboot.superSecretPassword="FIRST_CLASS_TICKETS_ca3e24ded9af48c01df28c830f192f95"

ENTRYPOINT ["java", "-cp", "classes:resources:libs/*", "com.united.TicketBoot.TicketBootApplication"]

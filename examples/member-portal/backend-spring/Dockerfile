FROM gradle:8.8-jdk17 AS build
WORKDIR /home/gradle/src

COPY remediate/ remediate/
COPY examples/member-portal/backend-spring/ examples/member-portal/backend-spring/

RUN gradle -p examples/member-portal/backend-spring bootJar --no-daemon

FROM eclipse-temurin:17-jre-alpine AS final
WORKDIR /app
COPY --from=build /home/gradle/src/examples/member-portal/backend-spring/build/libs/*.jar app.jar
EXPOSE 5002
ENTRYPOINT ["java", "-jar", "app.jar"]

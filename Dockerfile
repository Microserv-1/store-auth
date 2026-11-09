FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B verify
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=build /build/target/auth-1.0.0.jar app.jar
USER 10001
EXPOSE 8000
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-jar", "/app/app.jar"]

# FROM maven:3.9-eclipse-temurin-21 AS builder
# WORKDIR /app

# COPY pom.xml .
# RUN mvn -q -DskipTests dependency:go-offline

# COPY src ./src
# RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /api-gateway-assignment

COPY target/api-gateway-assignment-0.0.1-SNAPSHOT.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]

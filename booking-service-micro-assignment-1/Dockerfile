# FROM maven:3.9-eclipse-temurin-17 AS builder
# WORKDIR /app

# COPY pom.xml .
# RUN mvn -q -DskipTests dependency:go-offline

# COPY src ./src
# RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /booking-service-micro-assignment-1

COPY target/booking-service-micro-assignment-1-0.0.1-SNAPSHOT.jar

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]

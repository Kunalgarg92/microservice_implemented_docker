@echo off
echo Starting Eureka Server on Port 9997...
start "Eureka Server" cmd /k ^
java -jar Eureka-server-Registry-flightapp\target\Eureka-server-Registry-flightapp-0.0.1-SNAPSHOT.jar --server.port=9997 --eureka.client.register-with-eureka=false --eureka.client.fetch-registry=false

timeout /t 15

echo Starting Flight Service...
start "Flight Service" cmd /k ^
java -jar flight-service-micro-assignment\target\flight-service-micro-assignment-0.0.1-SNAPSHOT.jar --server.port=9999 --eureka.client.service-url.defaultZone=http://localhost:9997/eureka/

timeout /t 10

echo Starting Booking Service...
start "Booking Service" cmd /k ^
java -jar booking-service-micro-assignment-1\target\booking-service-micro-assignment-1-0.0.1-SNAPSHOT.jar --server.port=9998 --eureka.client.service-url.defaultZone=http://localhost:9997/eureka/

timeout /t 10

echo Starting API Gateway...
start "API Gateway" cmd /k ^
java -jar api-gateway-assignment\target\api-gateway-assignment-0.0.1-SNAPSHOT.jar --eureka.client.service-url.defaultZone=http://localhost:9997/eureka/

echo ===============================
echo All services started with Port Overrides
echo ===============================
FROM eclipse-temurin:21-jdk-jammy AS builder

WORKDIR /workspace

# Copy parent POM
COPY pom.xml .

# Copy auth-service
COPY auth-service/mvnw auth-service/mvnw
COPY auth-service/.mvn auth-service/.mvn
COPY auth-service/pom.xml auth-service/pom.xml
COPY auth-service/src auth-service/src

# Build the service
WORKDIR /workspace/auth-service
RUN chmod +x mvnw && ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre-jammy
RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring:spring

WORKDIR /app
COPY --from=builder /workspace/auth-service/target/*.jar app.jar

ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:InitialRAMPercentage=75.0 -XX:MaxRAMPercentage=75.0"
ENV RD_AUTH_SERVER_PORT=8081
ENV RD_AUTH_SERVER_HOST=localhost
EXPOSE 8081
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
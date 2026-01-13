FROM eclipse-temurin:21-jdk-jammy AS builder

WORKDIR /app
# Copy Maven wrapper and pom.xml
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Copy source code
COPY src ./src

# Build the service
RUN chmod +x mvnw && ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre-jammy
RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring:spring

WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar

ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:InitialRAMPercentage=75.0 -XX:MaxRAMPercentage=75.0"
ENV RD_AUTH_SERVER_PORT=8081
ENV RD_AUTH_SERVER_HOST=localhost
EXPOSE 8081
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
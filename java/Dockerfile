# ---- Build stage: compile with Maven (matches pom.xml: release 21) ----
FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

# ---- Runtime stage: slim JRE only ----
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/target/botwheel-bot-1.0.0.jar app.jar

# The bot reads config from env vars (TELEGRAM_BOT_TOKEN, MINIAPP_URL,
# TELEGRAM_SEED_FILE) — see BotConfig.load(). No args needed.
ENTRYPOINT ["java", "-cp", "app.jar", "com.botwheel.BotwheelBot"]

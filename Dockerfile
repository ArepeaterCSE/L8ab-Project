# مرحلة البناء
FROM maven:3.9.6-eclipse-temurin-17 AS build
COPY . .

# --- السطر السحري: تنظيف الملفات من شوائب الويندوز ---
RUN find src -name "*.java" -exec sed -i '1s/^\xEF\xBB\xBF//' {} +

# أمر البناء
RUN mvn clean package -DskipTests

# مرحلة التشغيل
FROM eclipse-temurin:17-jdk-jammy
COPY --from=build /target/security-platform-1.0.0-L8AB.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","app.jar"]

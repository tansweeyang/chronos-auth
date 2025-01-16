# The base image on which we would build our image
FROM openjdk:21-jdk-slim

# Install curl and maven
RUN apt-get update && apt-get install -y curl maven && apt-get clean

# Expose port 8080
EXPOSE 8080

# Set the working directory
WORKDIR /app

# Copy the pom.xml file to the working directory
COPY pom.xml .

# Resolve the dependencies in the pom.xml file
RUN mvn dependency:resolve

# Copy the source code to the working directory
COPY src src

# Build the project
RUN mvn clean package -DskipTests

# Copy the MySQL configuration file (e.g., mysqld.cnf) and set correct permissions
COPY mysql-config/mysqld.cnf /etc/mysql/conf.d/mysqld.cnf
RUN chmod 0444 /etc/mysql/conf.d/mysqld.cnf

# Set JVM memory options
ENV JAVA_OPTS="-Xmx512m -Xms256m -Xshare:on -XX:+UseSerialGC"

# Run the application
ENTRYPOINT ["java", "-jar", "target/application.jar"]
FROM maven:3-openjdk-11 AS build-env
WORKDIR /ws
COPY . /ws/
RUN mvn clean install

FROM shibme/dockerinspect-base
LABEL maintainer="shibme"
RUN mkdir -p /app
COPY --from=build-env /ws/target/dockerinspect-jar-with-dependencies.jar /app/dockerinspect.jar
WORKDIR /dockerinspect
CMD ["java","-jar","/app/dockerinspect.jar"]
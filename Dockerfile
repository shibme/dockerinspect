FROM shibme/dockerinspect-base
LABEL maintainer="shibme"
RUN mkdir -p ts-bin
COPY target/dockerinspect-jar-with-dependencies.jar /ts-bin/dockerinspect.jar
WORKDIR /dockerinspect
CMD ["java","-jar","/ts-bin/dockerinspect.jar"]
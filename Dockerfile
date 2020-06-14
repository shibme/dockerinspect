FROM shibme/dockerinspect-base
LABEL maintainer="shibme"
RUN mkdir -p ts-bin
COPY target/dockerinspect-jar-with-dependencies.jar /dockerinspect-bin/dockerinspect.jar
WORKDIR /dockerinspect
CMD ["java","-jar","/dockerinspect-bin/dockerinspect.jar"]
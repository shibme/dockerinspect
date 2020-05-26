FROM shibme/trivy-base
LABEL maintainer="shibme"
RUN mkdir -p ts-bin
COPY target/trivy-steward-jar-with-dependencies.jar /ts-bin/trivy-steward.jar
WORKDIR /trivy-steward
CMD ["java","-jar","/ts-bin/trivy-steward.jar"]
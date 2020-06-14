FROM ubuntu:bionic
LABEL maintainer="shibme"
RUN apt-get update && apt-get install -y wget apt-transport-https gnupg lsb-release wget openjdk-11-jre-headless
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
RUN echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list
RUN apt-get update && apt-get install trivy -y
WORKDIR /trivy
RUN trivy --download-db-only

FROM --platform=linux/amd64 openjdk:17-jdk-alpine
#FROM openjdk:17-jdk-alpine

RUN apk add --no-cache maven

COPY strutted /tmp/strutted
WORKDIR /tmp/strutted

RUN mvn clean package

FROM tomcat:9.0

RUN rm -rf /usr/local/tomcat/webapps/
RUN mv /usr/local/tomcat/webapps.dist/ /usr/local/tomcat/webapps/
RUN rm -rf /usr/local/tomcat/webapps/ROOT

COPY --from=0 /tmp/strutted/target/strutted-1.0.0.war /usr/local/tomcat/webapps/ROOT.war
COPY ./tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY ./context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml

EXPOSE 8080

CMD ["catalina.sh", "run"]

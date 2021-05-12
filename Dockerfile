FROM golang:1.16.3-alpine3.13 AS TRIVYPLUGIN
ADD . /src/compliance-hub-plugin-trivy
WORKDIR /src/compliance-hub-plugin-trivy
RUN go get -d
RUN go build -o /tmp/plugintrivy
RUN ls -lrt /tmp

FROM aquasec/trivy:0.16.0
WORKDIR /app
COPY --from=TRIVYPLUGIN /tmp/plugintrivy /app/plugintrivy
ENTRYPOINT /app/plugintrivy

FROM golang AS TRIVYPLUGIN
ADD . /src/compliance-hub-plugin-trivy
WORKDIR /src/compliance-hub-plugin-trivy
RUN go get -d
RUN go build -o /tmp/plugintrivy
RUN ls -lrt /tmp

FROM aquasec/trivy
WORKDIR /app
COPY --from=TRIVYPLUGIN /tmp/plugintrivy /app/plugintrivy
RUN ls -lrt /app
ENTRYPOINT /app/plugintrivy


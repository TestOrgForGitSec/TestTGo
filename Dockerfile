FROM golang:1.18.1-alpine3.15 AS TRIVYPLUGIN
ADD . /src/compliance-hub-plugin-trivy
WORKDIR /src/compliance-hub-plugin-trivy
ARG USER
ARG TOKEN
RUN apk --no-cache add git
RUN apk update
RUN apk add --no-cache pcre2-dev
RUN go env -w GOPRIVATE=github.com/deliveryblueprints/*
RUN git config --global url."https://${USER}:${TOKEN}@github.com".insteadOf  "https://github.com"
RUN go get -d
RUN go build -o /tmp/plugintrivy
RUN ls -lrt /tmp

FROM aquasec/trivy:0.27.1
WORKDIR /app
COPY --from=TRIVYPLUGIN /tmp/plugintrivy /app/plugintrivy
ENTRYPOINT /app/plugintrivy

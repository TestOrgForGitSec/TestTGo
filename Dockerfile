FROM golang:1.19-alpine AS GOLANG
WORKDIR /src
ARG USER
ARG TOKEN
RUN apk --no-cache add make git gcc libtool musl-dev ca-certificates dumb-init \
  && go install golang.org/x/vuln/cmd/govulncheck@latest \
  && go env -w GOPRIVATE=github.com/deliveryblueprints/* \
  && git config --global url."https://${USER}:${TOKEN}@github.com".insteadOf  "https://github.com" 
COPY . /src
RUN go mod download && go mod verify 
RUN go test -short ./... \
  && govulncheck ./... \
  && go build -o /tmp/myapp 

FROM aquasec/trivy:0.34.0
WORKDIR /app
RUN apk --no-cache add ca-certificates \
  && apk upgrade --no-cache libcurl \
  && adduser -DHSu 1001 nonpriv
USER nonpriv
COPY --from=GOLANG /tmp/myapp /app/myapp
ENTRYPOINT ["/app/myapp"]

ARG BASE_BUILD_IMAGE=golang:1.19-alpine
# final image ARG is not used as this has a custom trivy based image at present
ARG BASE_FINAL_IMAGE
ARG TRIVY_VERSION=0.44.0

FROM ${BASE_BUILD_IMAGE} AS GOLANG
WORKDIR /src
ARG USER
ARG TOKEN
RUN apk --no-cache add make git gcc libtool musl-dev ca-certificates dumb-init \
  && go install golang.org/x/vuln/cmd/govulncheck@latest \
  && go env -w GOPRIVATE=github.com/cloudbees-compliance/* \
  && git config --global url."https://${USER}:${TOKEN}@github.com".insteadOf  "https://github.com" 
COPY go.mod go.sum /src/
RUN go mod download && go mod verify 
COPY . /src
# run tests and govulncheck (but dont fail build if they fail)
RUN go test -short ./... \
  && govulncheck ./... || true
# build statically linked binary, include GIT details in ldflags
RUN GIT_COMMIT=$(git rev-list -1 HEAD) \
  && BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  && GIT_DESCRIBE=$(git describe --tags) \
  && go build -o /tmp/myapp \
        -ldflags="-linkmode 'external' -extldflags '-static' \
        -X 'main.GitCommitId=${GIT_COMMIT}' \
        -X 'main.BuildDate=${BUILD_DATE}' \
        -X 'main.GitDescribe=${GIT_DESCRIBE}'" \
  && go version /tmp/myapp

#NOTE: custom final image based on trivy upstream image
FROM aquasec/trivy:${TRIVY_VERSION}

ARG TRIVY_VERSION
WORKDIR /app

# Label
LABEL cbc.deps.trivy_version=${TRIVY_VERSION}

RUN apk --no-cache add ca-certificates \
  && apk upgrade --no-cache libcurl \
  && adduser -DHSu 1001 nonpriv
USER nonpriv
COPY --from=GOLANG /tmp/myapp /app/myapp
ENTRYPOINT ["/app/myapp"]

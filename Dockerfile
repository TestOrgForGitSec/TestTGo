FROM golang:1.16.3-alpine3.13
RUN apk --no-cache add ca-certificates git make
RUN mkdir /app
WORKDIR /source
ADD . /source/compliance-hub-plugin-trivy
RUN git clone https://github.com/aquasecurity/trivy.git
RUN cd /source/compliance-hub-plugin-trivy; go build -o /app/plugintrivy
RUN cd /source/trivy; make build

ENTRYPOINT ["/bin/sh"]
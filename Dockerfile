FROM alpine:3.12
RUN apk --no-cache add ca-certificates git make go
RUN mkdir /source
RUN cd /source
RUN git clone https://github.com/deliveryblueprints/compliance-hub-plugin-trivy.git
RUN git clone https://github.com/aquasecurity/trivy.git
RUN cd compliance-hub-plugin-trivy.git/api
RUN go build -o compliance-hub-plugin-trivy initiatescan.go
RUN mkdir /app/compliance-hub-plugin-trivy
RUN mkdir /app/trivy
ENTRYPOINT ["/bin/sh"]


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
FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
RUN CGO_ENABLED=0 go test -c -o /gateway.test ./internal/gateway

FROM nginx:stable-alpine@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311
COPY --from=build /gateway.test /checks/gateway.test
COPY examples/nginx.conf /checks/nginx.conf
ENV PORTER_NGINX=/usr/sbin/nginx
ENV PORTER_NGINX_CONFIG=/checks/nginx.conf
ENTRYPOINT ["/checks/gateway.test", "-test.run=TestNginxTrustBoundary", "-test.v"]

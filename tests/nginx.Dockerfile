FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
RUN CGO_ENABLED=0 go test -c -o /gateway.test ./internal/gateway

FROM nginx:stable-alpine
COPY --from=build /gateway.test /checks/gateway.test
COPY examples/nginx.conf /checks/nginx.conf
ENV PORTER_NGINX=/usr/sbin/nginx
ENV PORTER_NGINX_CONFIG=/checks/nginx.conf
ENTRYPOINT ["/checks/gateway.test", "-test.run=TestNginxTrustBoundary", "-test.v"]

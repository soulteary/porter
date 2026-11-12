FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS build
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

FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" -o /porter ./cmd/porter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /porter /porter
EXPOSE 8083 9093
ENTRYPOINT ["/porter"]
CMD ["serve", "-config", "/etc/porter/porter.json"]

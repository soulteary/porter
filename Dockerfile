FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /porter ./cmd/porter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /porter /porter
EXPOSE 8083
ENTRYPOINT ["/porter"]
CMD ["-config", "/etc/porter/porter.json"]

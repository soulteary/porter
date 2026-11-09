FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY tests/fixture ./cmd/acceptance-fixture
RUN CGO_ENABLED=0 go build -trimpath -o /fixture ./cmd/acceptance-fixture
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /fixture /fixture
ENTRYPOINT ["/fixture"]

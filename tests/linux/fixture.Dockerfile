FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY tests/fixture ./cmd/acceptance-fixture
COPY tests/linux/peer ./cmd/linux-peer
RUN CGO_ENABLED=0 go build -trimpath -o /fixture ./cmd/acceptance-fixture
RUN CGO_ENABLED=0 go build -trimpath -o /peer ./cmd/linux-peer
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /fixture /fixture
COPY --from=build /peer /peer
ENTRYPOINT ["/fixture"]

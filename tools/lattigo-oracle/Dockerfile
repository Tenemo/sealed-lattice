FROM golang:1.25.0-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a AS build

WORKDIR /source
COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY main.go ./

RUN CGO_ENABLED=0 go build \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w -buildid=" \
    -o /output/lattigo-oracle \
    .

FROM scratch

WORKDIR /oracle
COPY --from=build /output/lattigo-oracle ./lattigo-oracle
COPY sealed-lattice-canonical-rns-fixtures.json ./

USER 65532:65532
ENTRYPOINT ["/oracle/lattigo-oracle"]

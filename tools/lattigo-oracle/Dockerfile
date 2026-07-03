FROM golang:1.25.0-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a

WORKDIR /workspace/tools/lattigo-oracle
COPY tools/lattigo-oracle .

RUN go mod download && go mod verify

CMD ["go", "run", "-mod=readonly", "."]

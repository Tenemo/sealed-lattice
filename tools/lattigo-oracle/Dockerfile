FROM golang:1.25.0-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a

WORKDIR /workspace

COPY reference-projects/lattigo/upstream/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40 /workspace/reference-projects/lattigo/upstream/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40
COPY tools/lattigo-oracle /workspace/tools/lattigo-oracle

WORKDIR /workspace/tools/lattigo-oracle

RUN go mod tidy

CMD ["go", "run", "."]

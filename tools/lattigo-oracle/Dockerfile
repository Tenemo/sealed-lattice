FROM golang:1.25.0-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a

WORKDIR /workspace

COPY temp/lattigo/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40.zip /workspace/temp/lattigo/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40.zip
COPY tools/lattigo-oracle /workspace/tools/lattigo-oracle

WORKDIR /workspace/tools/lattigo-oracle

RUN echo "33c9049ea3c3eb0189b55619766a5bd07457de1c2c68565778a1253d9039d680  /workspace/temp/lattigo/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40.zip" | sha256sum -c - \
    && go run ./internal/extract-pinned-archive \
        -archive /workspace/temp/lattigo/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40.zip \
        -destination /workspace/temp/lattigo/upstream/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40 \
        -top-level lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40 \
    && go mod download \
    && go mod verify

CMD ["go", "run", "-mod=readonly", "."]

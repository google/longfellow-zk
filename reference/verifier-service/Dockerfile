# Stage 1: Create a dev image and run tests
FROM golang:latest AS builder
RUN apt update -y && apt install -y clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev
WORKDIR /reference/verifier-service/zk/
COPY lib /reference/verifier-service/zk/lib/
COPY /reference/verifier-service/server /reference/verifier-service/zk/server/
COPY lib/circuits/mdoc/circuits /reference/verifier-service/zk/server/circuits/LONGFELLOW_V1

RUN CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B build --install-prefix /reference/verifier-service/zk/install && \
    cd build && \
    make -j 16 install && \
    ctest -j 16

RUN cd server && \
    go mod download && \
    go build && \
    cd zk && go test -v

# Stage 2: Create a runtime image without dev
FROM golang:latest
WORKDIR /reference/verifier-service/zk/
RUN apt update -y && apt install -y libssl3 libzstd1 zlib1g
COPY --from=builder /reference/verifier-service/zk/server/circuits /reference/verifier-service/zk/circuits/
COPY --from=builder /reference/verifier-service/zk/server/server /reference/verifier-service/zk
COPY --from=builder /reference/verifier-service/zk/server/certs.pem /reference/verifier-service/zk
ENTRYPOINT ["/reference/verifier-service/zk/server"]
# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM debian:9.11 as build
RUN apt update && \ 
    apt install -y bash libprotobuf-dev \
                   libprotoc-dev protobuf-compiler \
                   libssl-dev libcurl4-openssl-dev uuid-dev

# To build iot-identity-service
RUN apt install -y \
    curl gcc g++ git jq make pkg-config cmake \
    libclang1 libssl-dev llvm-dev

# Install Rust & Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
ENV PATH="$PATH:/root/.cargo/bin"
RUN cargo install bindgen --version '^0.54' && \
    cargo install cbindgen --version '^0.15'

ADD . /
WORKDIR /eve-tools
RUN cp proto/api.proto . && \
    protoc --cpp_out=cpp api.proto && \
    make clean && make all && make install

RUN git clone https://github.com/Azure/iot-identity-service.git

# This diff iot-identity-service.diff is tied to commit id
# 15f59c8bd33b1fd8581a74ae6e5ea145c8cb1b9b of iot-identity-service
RUN cp /iot-identity-service.diff iot-identity-service/ && \
    cd iot-identity-service && \
    git reset --hard 15f59c8bd33b1fd8581a74ae6e5ea145c8cb1b9b && \
    git apply iot-identity-service.diff && \
    FORCE_NO_UNITTEST=1 make

RUN cp iot-identity-service/target/x86_64-unknown-linux-gnu/debug/aziotd /eve-tools/

FROM debian:9.11
COPY --from=build /eve-tools/aziotd .

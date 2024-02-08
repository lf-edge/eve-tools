# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM ubuntu:20.04 as build
ARG IOTD_COMMIT_ID=15f59c8bd33b1fd8581a74ae6e5ea145c8cb1b9b
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \ 
    apt-get install -y bash libprotobuf-dev libprotoc-dev protobuf-compiler \
                   libssl-dev libcurl4-openssl-dev uuid-dev g++ make cmake \
                   curl gcc g++ git jq pkg-config libclang1 llvm-dev

# Install Rust & Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
ENV PATH="$PATH:/root/.cargo/bin"
RUN cargo install bindgen --version '^0.54' && \
    cargo install cbindgen --version '^0.15'

# add source codes
ADD . /

# build eve-tools
WORKDIR /eve-tools
RUN make clean && make && make install

# build azure-on-eve
WORKDIR /azure-on-eve
RUN git submodule update --init --recursive && \
    mkdir build && cd build && \
    cmake -Drun_unittests=OFF -DUSE_TEST_TPM_INTERFACE_IN_MEM=OFF -DBUILD_SHARED=ON -Duse_cppunittest=OFF .. && \
    cmake --build .

# This diff iot-identity-service.diff is tied to commit id
# $IOTD_COMMIT_ID of iot-identity-service
WORKDIR /azure-on-eve/aziotd
RUN git clone https://github.com/Azure/iot-identity-service.git && \
    cp iot-identity-service.diff iot-identity-service/ && \
    cd iot-identity-service && \
    git reset --hard ${IOTD_COMMIT_ID} && \
    git apply iot-identity-service.diff && \
    FORCE_NO_UNITTEST=1 make && \
    cp target/x86_64-unknown-linux-gnu/debug/aziotd /azure-on-eve/aziotd/

# make the debian package
WORKDIR /azure-on-eve/deb
RUN /azure-on-eve/deb/make-deb.sh

FROM scratch
COPY --from=build /eve-tools/eve_run .
COPY --from=build /eve-tools/libevetools.so .
COPY --from=build /azure-on-eve/build/libiothsm.so.1.0.8 .
COPY --from=build /azure-on-eve/aziotd/aziotd .
COPY --from=build /azure-on-eve/deb/lfedge-eve-tools.deb .
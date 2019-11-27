# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM debian:9.11
RUN apt update && \ 
    apt install -y g++ make libprotobuf-dev \
                   libprotoc-dev protobuf-compiler \
                   cmake libssl-dev libcurl4-openssl-dev uuid-dev
ADD . /
WORKDIR /eve-tools
RUN cp proto/api.proto . && \
    protoc --cpp_out=cpp api.proto && \
    make clean && make all && make install

WORKDIR /azure-on-eve
RUN mkdir build && cd build && \
    cmake -Drun_unittests=OFF -DUSE_TEST_TPM_INTERFACE_IN_MEM=OFF -DBUILD_SHARED=ON -Duse_cppunittest=OFF .. && \
    cmake --build .

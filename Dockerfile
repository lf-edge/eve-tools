# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM debian:9.11
RUN apt update && \ 
    apt install -y g++ make libprotobuf-dev \
                   libprotoc-dev protobuf-compiler
ADD . /
WORKDIR /
RUN cp proto/api.proto . && \
    protoc --cpp_out=cpp api.proto && \
    make clean && make all && \
    cp libevetools.so /usr/lib

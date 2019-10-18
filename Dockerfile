FROM debian:9.11
RUN apt update
RUN apt install -y g++ make
RUN apt install -y libprotobuf-dev libprotoc-dev protobuf-compiler
ADD . /
WORKDIR /
RUN cp proto/api.proto .
RUN protoc --cpp_out=cpp api.proto
RUN make clean && make all
RUN cp libevetools.so /usr/lib

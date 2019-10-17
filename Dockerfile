FROM debian:9.11
RUN apt update
RUN apt install -y g++
RUN apt install -y libprotobuf-dev libprotoc-dev protobuf-compiler
ADD . /
RUN protoc --cpp_out=cpp proto/api.proto
RUN cp cpp/proto/* cpp/.
RUN g++ tools/ztpm_createkey.cpp cpp/api.pb.cc -I cpp/  -std=c++11 -lprotobuf
RUN apt install -y gdb

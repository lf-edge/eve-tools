libevetools.so: lib/src/sendrecv.cpp
	g++ -g -shared -fPIC -o libevetools.so lib/src/sendrecv.cpp -std=c++11 -lprotobuf
clean:
	rm -rf client libevetools.so *.dSYM ztpm2_createek 
ztpm2_createek: libevetools.so
	g++ tools/ztpm2_createek.cpp cpp/api.pb.cc -I cpp/  -std=c++11 -lprotobuf -g -L . libevetools.so -o ztpm2_createek

all: libevetools.so ztpm2_createek

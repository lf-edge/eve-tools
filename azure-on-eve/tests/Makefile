CFLAGS = -g -fpermissive -std=c++11 -lstdc++
BIN = "bin"
LDLIBS := /usr/lib/libevetools.so
INC= ./inc ../inc \
	../deps/c-shared/inc \
	../deps/c-shared/deps/umock-c/inc \
	../deps/c-shared/deps/azure-macro-utils-c/inc \
	../deps/utpm/inc

INC_PARAMS=$(foreach d, $(INC), -I$d)

all: $(BIN)/tpm_tests

clean:
	rm -f ./$(BIN)/*

test: $(BIN)/tpm_tests
	./run_tests.sh || true

$(BIN)/tpm_tests: tpm_tests.cpp
	@mkdir -p $(BIN)/
	$(CXX) $(CFLAGS) $(INC_PARAMS) \
	../deps/c-shared/src/xlogging.c \
	../deps/c-shared/src/consolelogger.c \
	../deps/utpm/src/Memory.c \
	../deps/utpm/src/Marshal.c \
	../src/hsm_client_tpm_select.c \
	../src/hsm_client_tpm_device.c \
	../src/hsm_log.c \
	tpm_tests.cpp -o $(BIN)/tpm_tests $(LDLIBS)

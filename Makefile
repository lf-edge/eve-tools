# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

TARGET ?= vtpm_server
INC_DIRS ?= ./lib/include ./cpp
LDLIBS := -lprotobuf -L . libevetools.so
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CPPFLAGS ?= $(INC_FLAGS) -std=c++11 -g
CC = g++

eve_run: libevetools.so
	$(CC) tools/eve_run.cpp cpp/api.pb.cc $(CPPFLAGS) -o eve_run $(LDLIBS)

libevetools.so: lib/src/sendrecv.cpp
	$(CC) $(CPPFLAGS) -shared -fPIC -o libevetools.so lib/src/sendrecv.cpp -lprotobuf

.PHONY: clean all

clean:
	rm -rf libevetools.so *.dSYM eve_run 

all: libevetools.so eve_run 

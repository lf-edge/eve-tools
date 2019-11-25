# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

INC_DIRS ?= ./lib/inc ./lib/src deps/c-shared/inc ./deps/c-shared/inc ./deps/c-shared/deps/azure-macro-utils-c/inc  ./deps/c-shared/deps/umock-c/inc ./deps/utpm/inc
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CPPFLAGS ?= $(INC_FLAGS) -g
CC = gcc

SOURCES := \
	lib/src/certificate_info.c \
	lib/src/constants.c \
	lib/src/edge_enc_openssl_key.c \
	lib/src/edge_hsm_client_crypto.c \
	lib/src/edge_hsm_client_store.c \
	lib/src/edge_hsm_client_x509.c \
	lib/src/edge_hsm_key_interface.c \
	lib/src/edge_openssl_common.c \
	lib/src/edge_pki_openssl.c \
	lib/src/edge_sas_key.c \
	lib/src/edge_sas_perform_sign_with_key.c \
	lib/src/hsm_certificate_props.c \
	lib/src/hsm_client_data.c \
	lib/src/hsm_client_tpm_device.c \
	lib/src/hsm_client_tpm_in_mem.c \
	lib/src/hsm_client_tpm_select.c \
	lib/src/hsm_log.c \
	lib/src/hsm_utils.c

libiothsm.so: 
	$(CC) $(CPPFLAGS) -shared -fPIC -o libiothsm.so $(SOURCES) 

.PHONY: clean all

clean:
	rm -rf libevetools.so *.dSYM eve_run 

all: libevetools.so

// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include "api.pb.h"
#include "eve_tpm_service.h"
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "sendrecv.h"

#define MAX_COMMAND_STR_LEN 4096

using namespace std;
using namespace google::protobuf::io;

static inline char *
prepare_payload (eve_tools::EveTPMRequest &request,  //IN
		char **payload,                      //OUT
		size_t *payload_size)                //OUT
{
    int size = request.ByteSize() + 4;
    char *pkt = new char [size];
    google::protobuf::io::ArrayOutputStream aos(pkt,size);
    CodedOutputStream *coded_output = new CodedOutputStream(&aos);
    coded_output->WriteVarint32(request.ByteSize());
    request.SerializeToCodedStream(coded_output);
    *payload = pkt;
    *payload_size = size;
    return 0;
}

static inline int
parse_response_buffer (char *payload,
		size_t payload_size,
		eve_tools::EveTPMResponse &response)
{
    google::protobuf::io::ArrayInputStream ais(payload, payload_size);
    CodedInputStream coded_input(&ais);
    google::protobuf::uint32 size;
    coded_input.ReadVarint32(&size);
    google::protobuf::io::CodedInputStream::Limit msgLimit = coded_input.PushLimit(size);
    response.ParseFromCodedStream(&coded_input);
    coded_input.PopLimit(msgLimit);
    return 0;
}

#define INITIALIZE(formatstr) \
    eve_tools::EveTPMRequest request;            \
    char command_str[MAX_COMMAND_STR_LEN];       \
    char *req_buf = NULL, *resp_buf = NULL;      \
    size_t req_buf_size = 0, resp_buf_size = 0;  \
    const char *format = formatstr;		 \
    int i = 0;                                   \

#define ADD_INPUT(input, input_size) \
    do {  \
        eve_tools::File *input_file = request.add_inputfiles(); \
        input_file->set_name(#input); \
        input_file->set_content(input, input_size); \
    }while(0);

#define ADD_OUTPUT(output) \
    request.add_expectedfiles(#output); \

#define PREP_TPM_CMD(args...) \
    do { \
        snprintf(command_str, MAX_COMMAND_STR_LEN, format, args); \
        request.set_command(command_str); \
        prepare_payload(request, &req_buf, &req_buf_size); \
    }while(0); \

#define SEND_TO_SERVER() \
	do { \
            int rc = sendrecv(req_buf, req_buf_size, (int *)&resp_buf_size, &resp_buf); \
            if (rc != 0) { \
                cout << "Failed to send request: " << rc << std::endl; \
                return rc; \
            }\
	}while (0);

#define PARSE_RESPONSE() \
	eve_tools::EveTPMResponse response; \
	parse_response_buffer(resp_buf, resp_buf_size, response); \
	if (response.response().find("ERROR") != response.response().npos) { \
		return -1; \
	} \


#define EXTRACT_OUTPUT(output_buf) \
        do { 								\
            const eve_tools::File& file = response.outputfiles(i++); \
	    string str = file.content(); \
            *output_buf  = (uint8_t*)new char[str.length()]; \
	    memcpy(*output_buf, str.c_str(), str.length()); \
	    *output_buf##_size = str.length(); \
	} while (0);

static int
__eve_tpm_service_activate_credential(
		uint8_t *session_context,
		size_t session_context_size,
		uint32_t credentialed_key_handle, //IN
		uint32_t credential_key_handle,   //IN
		uint8_t *cred_blob,               //IN
		size_t cred_blob_size,            //IN
		uint8_t **cert_info,              //OUT
		size_t *cert_info_size,           //OUT
		uint8_t **new_session_context,
		size_t *new_session_context_size
		) {

    INITIALIZE("tpm2_activatecredential -c 0x%x -C 0x%x -i %s -o %s -Psession:%s");
    ADD_INPUT(cred_blob, cred_blob_size);
    ADD_INPUT(session_context, session_context_size);
    ADD_OUTPUT(cert_info);
    ADD_OUTPUT(session_context);
    free(session_context);
    PREP_TPM_CMD(credentialed_key_handle, credential_key_handle,
		    "cred_blob", "cert_info", "session_context");
    SEND_TO_SERVER();
    PARSE_RESPONSE();
    EXTRACT_OUTPUT(cert_info);
    EXTRACT_OUTPUT(new_session_context);

    return 0;
}


static int
__eve_tpm_service_import(
		int32_t parent_key_handle,        //IN
		uint8_t *encryption_key,           //IN
		size_t encryption_key_size,        //IN
		uint8_t *public_key,               //IN
		size_t public_key_size,            //IN
		uint8_t *duplicate_key_blob,       //IN
		size_t duplicate_key_size,         //IN
		uint8_t *kdf_seed,                 //IN
		size_t kdf_seed_size,              //IN
		uint8_t **private_key,             //OUT
		size_t *private_key_size           //OUT
		) {
    INITIALIZE("tpm2_import -C 0x%x -k encryption_key -u public_key -r private_key -i duplicate_key_blob -s kdf_seed -L dpolicy.dat");
    ADD_INPUT(encryption_key, encryption_key_size);
    ADD_INPUT(public_key, public_key_size);
    ADD_INPUT(duplicate_key_blob, duplicate_key_size);
    ADD_INPUT(kdf_seed, kdf_seed_size);
    ADD_OUTPUT(private_key);
    PREP_TPM_CMD(parent_key_handle);
    SEND_TO_SERVER();
    PARSE_RESPONSE();
    EXTRACT_OUTPUT(private_key);

    return 0;
}

static int
__eve_tpm_service_load(
		uint32_t parent_key_handle,        //IN
		uint8_t *key_public,               //IN
		size_t key_public_size,            //IN
		uint8_t *key_private,              //IN
		size_t key_private_size,           //IN
		uint8_t **loaded_key_context,      //OUT
		size_t *loaded_key_context_size   //OUT
		) {
    INITIALIZE("tpm2_load -C 0x%x -u key_public -r key_private -c loaded_key_context");
    ADD_INPUT(key_public, key_public_size);
    ADD_INPUT(key_private, key_private_size);
    ADD_OUTPUT(loaded_key_context);
    PREP_TPM_CMD(parent_key_handle);
    SEND_TO_SERVER();
    PARSE_RESPONSE();
    EXTRACT_OUTPUT(loaded_key_context);

    return 0;
}

static int
__eve_tpm_service_evictcontrol(
		uint32_t persistent_handle,         //IN
		uint8_t *object_context,            //IN
		size_t object_context_size          //IN
		) {
    INITIALIZE("tpm2_evictcontrol -c %s 0x%x");
    if (object_context) {
        ADD_INPUT(object_context, object_context_size);
    }
    PREP_TPM_CMD(object_context ? "object_context": "",
		    persistent_handle);
    SEND_TO_SERVER();

    return 0;
}

static int
__eve_tpm_service_startauthsession(
		uint8_t **session_context,          //OUT
		size_t *session_context_size        //OUT
		) {
    INITIALIZE("tpm2_startauthsession --policy-session -S %s");
    ADD_OUTPUT(session_context);
    PREP_TPM_CMD("session_context");
    SEND_TO_SERVER();
    PARSE_RESPONSE();
    EXTRACT_OUTPUT(session_context);
    return 0;
}

static int
__eve_tpm_service_flushcontext(
		uint8_t *session_context,           //IN
		size_t session_context_size         //IN
		) {
	INITIALIZE("tpm2_flushcontext %s");
	ADD_INPUT(session_context, session_context_size);
	PREP_TPM_CMD("session_context");
	SEND_TO_SERVER();
	PARSE_RESPONSE();
	delete(session_context);
	return 0;
}

static int
__eve_tpm_service_policysecret(
		uint8_t *session_context,           //IN
		size_t session_context_size,        //IN
		uint32_t object_handle,             //IN
		uint8_t **new_session_context,      //OUT
		size_t *new_session_context_size    //OUT
		) {
	INITIALIZE("tpm2_policysecret -S %s -c 0x%X");
	ADD_INPUT(session_context, session_context_size);
	ADD_OUTPUT(session_context);
	free(session_context);
	PREP_TPM_CMD("session_context", object_handle);
	SEND_TO_SERVER();
	PARSE_RESPONSE();
	EXTRACT_OUTPUT(new_session_context);
	return 0;
}

static int
__eve_tpm_service_readpublic(
		uint32_t handle,                  //IN
		uint8_t *context,                 //IN
		size_t context_size,              //IN
		PUB_KEYOUT_FORMAT kformat,        //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		) {
	INITIALIZE("tpm2_readpublic -c %s -o %s -f %s");
	if (!handle && !context) {
		return -1;
	}
	ADD_OUTPUT(key_public);
	if (handle) {
		format = "tpm2_readpublic -c 0x%x -o %s -f %s";
		PREP_TPM_CMD(handle, "key_public", pubkeyformat_to_str(kformat));
	} else if (context) {
		PREP_TPM_CMD("context", "key_public", pubkeyformat_to_str(kformat));
		ADD_INPUT(context, context_size);
	}
	SEND_TO_SERVER();
	PARSE_RESPONSE();
	EXTRACT_OUTPUT(key_public);
	return 0;
}

static int
__eve_tpm_service_hmac(
		uint8_t *key_context,             //IN
		size_t key_context_size,          //IN
		HASH hash,                        //IN
		const uint8_t *data_to_be_signed, //IN
		size_t data_to_be_signed_size,    //IN
		uint8_t **digest,                 //OUT
		size_t *digest_size               //OUT
		) {
	INITIALIZE("tpm2_hmac -c %s -g %s -o %s %s");
	ADD_INPUT(data_to_be_signed, data_to_be_signed_size);
	ADD_INPUT(key_context, key_context_size);
	ADD_OUTPUT(digest);
	PREP_TPM_CMD("key_context", hash_to_str(hash),
		      "digest", "data_to_be_signed");
	SEND_TO_SERVER();
	PARSE_RESPONSE();
	EXTRACT_OUTPUT(digest);
    return 0;
}

extern "C" {

int
eve_tpm_service_activate_credential(
		uint8_t *session_context,
		size_t session_context_size,
		uint32_t credentialed_key_handle, //IN
		uint32_t credential_key_handle,   //IN
		uint8_t *cred_blob,               //IN
		size_t cred_blob_size,            //IN
		uint8_t **cert_info,              //OUT
		size_t *cert_info_size,           //OUT
		uint8_t **new_session_context,
		size_t *new_session_context_size
		)
{
	return __eve_tpm_service_activate_credential(
			session_context,
			session_context_size,
			credentialed_key_handle,
			credential_key_handle,
			cred_blob,
			cred_blob_size,
			cert_info,
			cert_info_size,
			new_session_context,
			new_session_context_size
			);
}



int
eve_tpm_service_import(
		uint32_t parent_key_handle,        //IN
		uint8_t *encryption_key,           //IN
		size_t encryption_key_size,        //IN
		uint8_t *public_key,               //IN
		size_t public_key_size,            //IN
		uint8_t *duplicate_key_blob,       //IN
		size_t duplicate_key_size,         //IN
		uint8_t *kdf_seed,                 //IN
		size_t kdf_seed_size,              //IN
		uint8_t **private_key,             //OUT
		size_t *private_key_size           //OUT
		)
{
	return __eve_tpm_service_import(
			parent_key_handle,
			encryption_key,
			encryption_key_size,
			public_key,
			public_key_size,
			duplicate_key_blob,
			duplicate_key_size,
			kdf_seed,
			kdf_seed_size,
			private_key,
			private_key_size);

}

int
eve_tpm_service_load(
		uint32_t parent_key_handle,        //IN
		uint8_t *key_public,               //IN
		size_t key_public_size,            //IN
		uint8_t *key_private,              //IN
		size_t key_private_size,           //IN
		uint8_t **loaded_key_context,      //OUT
		size_t *loaded_key_context_size    //OUT
		)
{
	return __eve_tpm_service_load(
			parent_key_handle,
			key_public,
			key_public_size,
			key_private,
			key_private_size,
			loaded_key_context,
			loaded_key_context_size);
}


int
eve_tpm_service_evictcontrol(
		uint32_t persistent_handle,         //IN
		uint8_t *object_context,            //IN
		size_t object_context_size          //IN
		)
{
	return __eve_tpm_service_evictcontrol(
			persistent_handle,
			object_context,
			object_context_size);
}


int
eve_tpm_service_startauthsession(
		uint8_t **session_context,          //OUT
		size_t *session_context_size        //OUT
		)
{
	return __eve_tpm_service_startauthsession(
			session_context,
			session_context_size);
}

int
eve_tpm_service_flushcontext(
		uint8_t *session_context,           //IN
		size_t session_context_size         //IN
		)
{
	return __eve_tpm_service_flushcontext(
			session_context,
			session_context_size);
}

int
eve_tpm_service_policysecret(
		uint8_t *session_context,           //IN
		size_t session_context_size,        //IN
		uint32_t object_handle,    	    //IN
		uint8_t **new_session_context,      //OUT
		size_t *new_session_context_size    //OUT
		)
{
	return __eve_tpm_service_policysecret(
			session_context,
			session_context_size,
			object_handle,
			new_session_context,
			new_session_context_size);
}

int
eve_tpm_service_readpublic(
		uint32_t handle,                  //IN
		uint8_t *context,                 //IN
		size_t context_size,              //IN
		PUB_KEYOUT_FORMAT format,         //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		)
{
	return __eve_tpm_service_readpublic(
			handle,
			context,
			context_size,
			format,
			key_public,
			key_public_size);
}

int
eve_tpm_service_hmac(
		uint8_t *key_context,             //IN
		size_t key_context_size,          //IN
		HASH hash,                        //IN
		const uint8_t *data_to_be_signed, //IN
		size_t data_to_be_signed_size,    //IN
		uint8_t **digest,                 //OUT
		size_t *digest_size               //OUT
		)
{
	return __eve_tpm_service_hmac(
			key_context,
			key_context_size,
			hash,
			data_to_be_signed,
			data_to_be_signed_size,
			digest,
			digest_size);
}
} //extern "C"


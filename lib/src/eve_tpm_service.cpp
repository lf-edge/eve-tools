// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>	
#include <iostream>
#include "api.pb.h"
#include "eve_tpm_service.h"
#include "sendrecv.h"

static int
__eve_tpm_service_activate_credential(
		uint32_t credentialed_key_handle, //IN
		uint32_t credential_key_handle,   //IN
		uint8_t *cred_blob,               //IN
		size_t cred_blob_size,            //IN
		uint8_t **cert_info,              //OUT
		size_t *cert_info_size            //OUT
		) { 

    eve_tools::EveTPMRequest request;
    eve_tools::File *input_file = request.add_inputfiles();
    input_file->set_name("cred_blob");
    input_file->set_content(cred_blob, cred_blob_size);

    ostringstream command;
    command << "tpm2_activatecredential"
	<< " -c 0x" << std::hex << credentialed_key_handle
	<< " -C 0x" << std::hex << credential_key_handle
        << " -i " << "cred_blob"
        << " -o " << "cert_info"
	<< " -P \"session:session.ctx\""
    request.set_command(command.str());

    return 0;
}


static int
__eve_tpm_service_import(
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
		) { return 0; }

static int
__eve_tpm_service_load(
		uint32_t parent_key_handle,        //IN
		uint8_t *key_public,               //IN
		size_t key_public_size,            //IN
		uint8_t *key_private,              //IN
		size_t key_private_size,           //IN
		uint8_t **loaded_key_context,      //OUT
		size_t *loaded_key_context_size   //OUT
		) { return 0; }


static int
__eve_tpm_service_evictcontrol(
		uint32_t persistent_handle,         //IN
		uint8_t *object_context,            //IN
		size_t object_context_size          //IN
		) { return 0; }


static int
__eve_tpm_service_startauthsession(
		uint8_t **session_context,          //OUT
		size_t *session_context_size        //OUT
		) { return 0; }

static int
__eve_tpm_service_flushcontext(
		uint8_t *session_context,           //IN
		size_t session_context_size         //IN
		) { return 0; }

static int
__eve_tpm_service_policysecret(
		uint8_t *session_context,           //IN
		size_t session_context_size,        //IN
		uint32_t object_handle              //IN
		) { return 0; }


static int
__eve_tpm_service_createprimary(
		uint32_t persistent_handle,       //IN
		HEIRARCHY hierarchy,              //IN
		ALG algorithm,                    //IN
		HASH hash,                        //IN
		uint8_t **context,                //OUT
		size_t *context_size              //OUT
		) { return 0; }

static int
__eve_tpm_service_createek(
		uint32_t persistent_handle,       //IN
		ALG algorithm,                    //IN
		PUB_KEYOUT_FORMAT format,         //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		) { return 0; }

static int
__eve_tpm_service_readpublic(
		uint8_t *context,                 //IN
		size_t context_size,              //IN
		PUB_KEYOUT_FORMAT format,         //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		) { return 0; }

static int
__eve_tpm_service_hmac(
		uint32_t key_handle,              //IN
		HASH hash,                        //IN
		uint8_t *data_to_be_signed,       //IN
		size_t data_to_be_signed_size,    //IN
		uint8_t **digest,                 //OUT
		size_t *digest_size               //OUT
		) { return 0; }

int
eve_tpm_service_activate_credential(
		uint32_t credentialed_key_handle, //IN
		uint32_t credential_key_handle,   //IN
		uint8_t *cred_blob,               //IN
		size_t cred_blob_size,            //IN
		uint8_t **cert_info,              //OUT
		size_t *cert_info_size            //OUT
		)
{
	return __eve_tpm_service_activate_credential(
			credentialed_key_handle,
			credential_key_handle,
			cred_blob,
			cred_blob_size,
			cert_info,
			cert_info_size
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
		uint32_t object_handle             //IN
		)
{
	return __eve_tpm_service_policysecret(
			session_context,
			session_context_size,
			object_handle);
}

int
eve_tpm_service_createprimary(
		uint32_t persistent_handle,       //IN
		HEIRARCHY hierarchy,              //IN
		ALG algorithm,                    //IN
		HASH hash,                        //IN
		uint8_t **context,                //OUT
		size_t *context_size              //OUT
		)
{
	return __eve_tpm_service_createprimary(
			persistent_handle,
			hierarchy,
			algorithm,
			hash,
			context,
			context_size);
}

int
eve_tpm_service_createek(
		uint32_t persistent_handle,       //IN
		ALG algorithm,                    //IN
		PUB_KEYOUT_FORMAT format,         //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		)
{
	return __eve_tpm_service_createek(
			persistent_handle,
			algorithm,
			format,
			key_public,
			key_public_size);
}

int
eve_tpm_service_readpublic(
		uint8_t *context,                 //IN
		size_t context_size,              //IN
		PUB_KEYOUT_FORMAT format,         //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		)
{
	return __eve_tpm_service_readpublic(
			context,
			context_size,
			format,
			key_public,
			key_public_size);
}

int
eve_tpm_service_hmac(
		uint32_t key_handle,              //IN
		HASH hash,                        //IN
		uint8_t *data_to_be_signed,       //IN
		size_t data_to_be_signed_size,    //IN
		uint8_t **digest,                 //OUT
		size_t *digest_size               //OUT
		)
{
	return __eve_tpm_service_hmac(
			key_handle,
			hash,
			data_to_be_signed,
			data_to_be_signed_size,
			digest,
			digest_size);
}


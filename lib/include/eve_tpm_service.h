// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVE_TPM_SERVICE_H
#define EVE_TPM_SERVICE_H

/** @file */
#ifdef __cplusplus
extern "C" {
#endif 

extern int
eve_tpm_service_activate_credential(
		uint32_t credentialed_key_handle, //IN
		uint32_t credential_key_handle,   //IN
		uint8_t *cred_blob,               //IN
		size_t cred_blob_size,            //IN
		uint8_t **cert_info,              //OUT
		size_t *cert_info_size            //OUT
		);


extern int
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
		);
extern int
eve_tpm_service_load(
		uint32_t parent_key_handle,        //IN
		uint8_t *key_public,               //IN
		size_t key_public_size,            //IN
		uint8_t *key_private,              //IN
		size_t key_private_size,           //IN
		uint8_t **loaded_key_context,      //OUT
		size_t *loaded_key_context_size    //OUT
		);


extern int
eve_tpm_service_evictcontrol(
		uint32_t persistent_handle,         //IN
		uint8_t *object_context,            //IN
		size_t object_context_size          //IN
		);


extern int
eve_tpm_service_startauthsession(
		uint8_t **session_context,          //OUT
		size_t *session_context_size        //OUT
		);

extern int
eve_tpm_service_flushcontext(
		uint8_t *session_context,           //IN
		size_t session_context_size         //IN
		);

extern int
eve_tpm_service_policysecret(
		uint8_t *session_context,           //IN
		size_t session_context_size,        //IN
		uint32_t object_handle              //IN
		);

typedef enum {
	RSA,
	AES128CFB,
}ALG;


static inline const char *
alg_to_str(ALG alg)
{
	switch(alg) {
		case RSA:
			return "rsa";
		case AES128CFB:
			return "aes128:cfb";
		default:
			return "unknown";
	}
}

typedef enum {
	TSS,
	PEM,
}PUB_KEYOUT_FORMAT;


static inline const char *
pubkeyformat_to_str(PUB_KEYOUT_FORMAT format)
{
	switch(format) {
		case TSS:
			return "tss";
		case PEM:
			return "pem";
		default:
			return "unknown";
	}
}

typedef enum {
	ENDORSEMENT,
	OWNER,
	PLATFORM,
}HEIRARCHY;

typedef enum {
	SHA256,
	SHA384,
}HASH;


static inline const char *
hash_to_str(HASH hash)
{
	switch(hash) {
		case SHA256:
			return "sha256";
		case SHA384:
		default:
			return "unknown";
	}
}

static inline const char *
hierarchy_to_str(HEIRARCHY h)
{
	switch (h) {
		case ENDORSEMENT:
			return "e";
		case PLATFORM:
			return "p";
		case OWNER:
			return "o";
		default:
			return "unknown";
	}
}

extern int
eve_tpm_service_createprimary(
		uint32_t persistent_handle,       //IN
		HEIRARCHY hierarchy,              //IN
		ALG algorithm,                    //IN
		HASH hash,                        //IN
		uint8_t **context,                //OUT
		size_t *context_size    	  //OUT
		);

extern int
eve_tpm_service_createek(
		uint32_t persistent_handle,       //IN
		ALG algorithm,                    //IN
		PUB_KEYOUT_FORMAT format,         //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		);

extern int
eve_tpm_service_readpublic(
		uint8_t *context,                 //IN
		size_t context_size,              //IN
		PUB_KEYOUT_FORMAT format,         //IN
		uint8_t **key_public,             //OUT
		size_t *key_public_size           //OUT
		);

extern int
eve_tpm_service_hmac(
		uint32_t key_handle,              //IN
		HASH hash,                        //IN
		uint8_t *data_to_be_signed,       //IN
		size_t data_to_be_signed_size,    //IN
		uint8_t **digest,                 //OUT
		size_t *digest_size               //OUT
		);

#ifdef __cplusplus
} //extern "C"
#endif 
#endif //EVE_TPM_SERVICE_H

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/// Derived fom azure-iot-sdk-c library's provisioning client.
/// https://github.com/Azure/azure-iot-sdk-c/blob/master/provisioning_client/src/secure_device_tpm.c

#include <stdlib.h>
#include <stdbool.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/sastoken.h"
#include "azure_c_shared_utility/sha.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_utpm_c/tpm_comm.h"
#include "azure_utpm_c/tpm_codec.h"
#include "azure_utpm_c/Marshal_fp.h"     // for activation blob unmarshaling

#include "hsm_client_data.h"
#include "hsm_err.h"
#include "hsm_log.h"
#include "eve_tpm_service.h"


#define TPM_MAX_DATA_LENGTH 4096

static const uint32_t TPM_20_SRK_HANDLE = 0x81000001;
static const uint32_t TPM_20_EK_HANDLE =  0x81010001;
static const uint32_t DPS_ID_KEY_HANDLE = 0x81000100;

typedef struct HSM_CLIENT_INFO_TAG
{
    uint8_t *ek_pub;
    size_t ek_pub_size;

    uint8_t *srk_pub;
    size_t srk_pub_size;

    TPM2B_PUBLIC id_key_public;
    TPM2B_PRIVATE id_key_dup_blob;
    TPM2B_PRIVATE id_key_priv;
} HSM_CLIENT_INFO;


#define DPS_UNMARSHAL(Type, pValue) \
{                                                                       \
    TPM_RC rc = Type##_Unmarshal(pValue, &curr_pos, (INT32*)&act_size);         \
    if (rc != TPM_RC_SUCCESS)                                           \
    {                                                                   \
        LOG_ERROR(#Type"_Unmarshal() for " #pValue " failed");           \
    }                                                                   \
}

#define DPS_MARSHAL(Type, pValue, pBuffer, size) \
{                                                                       \
    buflen = Type##_Marshal(pValue, &pBuffer, (INT32*)&size);      \
}

#define DPS_UNMARSHAL_FLAGGED(Type, pValue) \
{                                                                       \
    TPM_RC rc = Type##_Unmarshal(pValue, &curr_pos, (INT32*)&act_size, TRUE);   \
    if (rc != TPM_RC_SUCCESS)                                           \
    {                                                                   \
        LOG_ERROR(#Type"_Unmarshal() for " #pValue " failed");           \
    }                                                                   \
}

#define DPS_UNMARSHAL_ARRAY(dstPtr, arrSize) \
    DPS_UNMARSHAL(uint32_t, &(arrSize));                                          \
    printf("act_size %d < actSize %d\r\n", act_size, arrSize);   \
    if (act_size < arrSize)                                                     \
    {                                                                           \
        LOG_ERROR("Unmarshaling " #dstPtr " failed: Need %d bytes, while only %d left", arrSize, act_size);  \
        result = __FAILURE__;       \
    }                                                                           \
    else                            \
    {                                   \
        dstPtr = curr_pos - sizeof(uint16_t);                                         \
        *(uint16_t*)dstPtr = (uint16_t)arrSize;                                         \
        curr_pos += arrSize;                         \
    }

#if 0
static size_t
size_of_file (const char *filename)
{
	FILE *pFile = fopen(filename, "r");
	unsigned int lSize = 0;
	if (pFile) {
		fseek (pFile , 0 , SEEK_END);
		lSize = ftell (pFile);
		fclose(pFile);
	}
	return (size_t)lSize;
}

static int
read_from_file_to_buf (const char *filename, size_t *buflen, unsigned char **buf)
{
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		return 0;
	}
	*buflen = size_of_file(filename);
	*buf = (unsigned char *)malloc(sizeof(char) * (*buflen));
	if (*buf == NULL) {
		return -1;
	}
	fread(*buf, *buflen, 1, fp);
	fclose(fp);
	return 0;
}
#endif 

static bool tpm2_util_is_big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

#define STRING_BYTES_ENDIAN_CONVERT(size) \
    UINT##size tpm2_util_endian_swap_##size(UINT##size data) { \
    \
        UINT##size converted; \
        UINT8 *bytes = (UINT8 *)&data; \
        UINT8 *tmp = (UINT8 *)&converted; \
    \
        size_t i; \
        for(i=0; i < sizeof(UINT##size); i ++) { \
            tmp[i] = bytes[sizeof(UINT##size) - i - 1]; \
        } \
        \
        return converted; \
    }

STRING_BYTES_ENDIAN_CONVERT(16)
STRING_BYTES_ENDIAN_CONVERT(32)

#define BE_CONVERT(value, size) \
    do { \
        if (!tpm2_util_is_big_endian()) { \
            value = tpm2_util_endian_swap_##size(value); \
        } \
    } while (0)

static uint8_t* writex(uint8_t *buf, uint8_t *data, size_t size) {
    memcpy(buf, data, size);
    return buf + size;
}

#define BUFFER_WRITE(size) \
    uint8_t* buffer_write_##size(uint8_t *buf, uint##size##_t data) { \
        BE_CONVERT(data, size); \
        return writex(buf, (uint8_t *)&data, sizeof(data)); \
    } \

/**
 * This is the magic for the file header. The header is organized
 * as a big endian U32 (BEU32) of MAGIC followed by a BEU32 of the
 * version number. Tools can define their own, individual file
 * formats as they make sense, but they should always have the header.
 */
static const uint32_t MAGIC = 0xBADCC0DE;

BUFFER_WRITE(16)
BUFFER_WRITE(32)


static uint8_t* buffer_write_bytes(uint8_t *buf, uint8_t bytes[], size_t len) {
    return writex(buf, bytes, len);
}

static uint8_t*  buffer_write_header(uint8_t *out, uint32_t version) {
    out = buffer_write_32(out, MAGIC);
    out = buffer_write_32(out, version);
    return out;
}

static inline int
prepare_cred_blob(TPM2B_ID_OBJECT *enc_key_blob,
		TPM2B_ENCRYPTED_SECRET *tpm_enc_secret,
		uint8_t **cred_blob,
		size_t *cred_blob_size)
{
#define TPM_UTIL_HDR_LEN ((sizeof(uint32_t) *2))
	*cred_blob = (uint8_t *) malloc(sizeof(uint8_t) * 
		                (TPM_UTIL_HDR_LEN +  //header 
				enc_key_blob->t.size + //enc_key_blob
			       	tpm_enc_secret->t.size + //tpm_enc_secret
				(2*sizeof(uint16_t)))); //size fields of both blobs
        uint8_t *moving_ptr = *cred_blob;
	moving_ptr = buffer_write_header(moving_ptr, 1);
	moving_ptr = buffer_write_16(moving_ptr, enc_key_blob->t.size);
	moving_ptr = buffer_write_bytes(moving_ptr,
		enc_key_blob->t.credential, enc_key_blob->t.size); 
	moving_ptr = buffer_write_16(moving_ptr, tpm_enc_secret->t.size);
	moving_ptr = buffer_write_bytes(moving_ptr, 
		tpm_enc_secret->t.secret, tpm_enc_secret->t.size);
	*cred_blob_size = (size_t)(moving_ptr - *cred_blob);
	return 0;

}
static int insert_key_in_tpm
(
    const unsigned char* key,
    size_t key_len
)
{
	int result = 0;
	TPM2B_ID_OBJECT enc_key_blob;
	TPM2B_ENCRYPTED_SECRET tpm_enc_secret;
	TPM2B_PRIVATE id_key_dup_blob;
	TPM2B_ENCRYPTED_SECRET encrypt_wrap_key;
	TPM2B_PUBLIC id_key_Public;

	uint8_t* curr_pos = (uint8_t*)key;
	uint32_t act_size = (int32_t)key_len;
	memset(&id_key_Public, 0, sizeof(TPM2B_PUBLIC));
	id_key_Public.size = 0;
	id_key_Public.publicArea.type = TPM_ALG_NULL;
	DPS_UNMARSHAL(TPM2B_ID_OBJECT, &enc_key_blob);
	DPS_UNMARSHAL(TPM2B_ENCRYPTED_SECRET, &tpm_enc_secret);
	DPS_UNMARSHAL(TPM2B_PRIVATE, &id_key_dup_blob);
	DPS_UNMARSHAL(TPM2B_ENCRYPTED_SECRET, &encrypt_wrap_key);
	DPS_UNMARSHAL_FLAGGED(TPM2B_PUBLIC, &id_key_Public);

	uint8_t duplicate_key_blob[TPM_MAX_DATA_LENGTH];
	size_t duplicate_key_blob_size = 0;
	uint8_t *pBuf = duplicate_key_blob;
	uint16_t buflen = 0;
	size_t max_len = TPM_MAX_DATA_LENGTH;
	DPS_MARSHAL(TPM2B_PRIVATE, &id_key_dup_blob, pBuf, max_len);
	duplicate_key_blob_size = buflen;

	uint8_t kdf_seed[TPM_MAX_DATA_LENGTH];
	size_t kdf_seed_size = 0;
	pBuf = kdf_seed;
	buflen = 0;
	DPS_MARSHAL(TPM2B_ENCRYPTED_SECRET, &encrypt_wrap_key, pBuf, max_len);
	kdf_seed_size = buflen;

	uint8_t public_key[TPM_MAX_DATA_LENGTH];
	size_t public_key_size = 0;
	pBuf = public_key;
	buflen = 0;
	DPS_MARSHAL(TPM2B_PUBLIC, &id_key_Public, pBuf, max_len);
	public_key_size = buflen;

	uint8_t *cred_blob = NULL;
        size_t cred_blob_size = 0;
	uint8_t *session_context = NULL;
	size_t session_context_size = 0;
	uint8_t *encryption_key = NULL;
	size_t encryption_key_size = 0;
	
	prepare_cred_blob(&enc_key_blob, &tpm_enc_secret,
			&cred_blob, &cred_blob_size);
	eve_tpm_service_startauthsession(&session_context, &session_context_size);
        eve_tpm_service_policysecret(session_context, session_context_size, 0x4000000B,
			&session_context, &session_context_size);
	eve_tpm_service_activate_credential(TPM_20_SRK_HANDLE, 
			TPM_20_EK_HANDLE, 
			cred_blob,
			cred_blob_size,
			&encryption_key,
			&encryption_key_size); 
        eve_tpm_service_flushcontext(session_context, session_context_size);
	free(cred_blob);

	uint8_t *private_key = NULL;
	size_t private_key_size = 0;
	eve_tpm_service_startauthsession(&session_context, &session_context_size);
        eve_tpm_service_policysecret(session_context, session_context_size, 0x4000000B,
			&session_context, &session_context_size);
        eve_tpm_service_import(TPM_20_SRK_HANDLE,
			 encryption_key, encryption_key_size,
			 public_key, public_key_size,
			 duplicate_key_blob, duplicate_key_blob_size,
			 kdf_seed, kdf_seed_size, 
			 &private_key, &private_key_size);
	eve_tpm_service_flushcontext(session_context, session_context_size);
	free(encryption_key);
	
	uint8_t *loaded_key_context = NULL;
	size_t  loaded_key_context_size = 0;
	eve_tpm_service_load(TPM_20_SRK_HANDLE,
			public_key, public_key_size,
			private_key, private_key_size,
			&loaded_key_context, &loaded_key_context_size);
	eve_tpm_service_evictcontrol(DPS_ID_KEY_HANDLE, NULL, 0);
	eve_tpm_service_evictcontrol(DPS_ID_KEY_HANDLE, loaded_key_context, loaded_key_context_size);
	free(loaded_key_context);

	return result;
}

static int initialize_tpm_device(HSM_CLIENT_INFO *handle)
{
    int result = 0;
    eve_tpm_service_readpublic(TPM_20_EK_HANDLE, NULL, 0, TSS, &handle->ek_pub,
		                &handle->ek_pub_size); 
    if (handle->ek_pub == NULL) {
	    eve_tpm_service_createek(TPM_20_EK_HANDLE, RSA, TSS, &handle->ek_pub, 
			             &handle->ek_pub_size); 
    }
    eve_tpm_service_readpublic(TPM_20_SRK_HANDLE, NULL, 0, TSS, &handle->srk_pub,
		                    &handle->srk_pub_size); 
    if (handle->srk_pub == NULL) {
	    uint8_t *srk_context = NULL;
	    size_t srk_context_size = 0;
	    eve_tpm_service_createprimary(TPM_20_SRK_HANDLE, ENDORSEMENT, RSA, EVE_SHA256,
			                  &srk_context, &srk_context_size);
	    eve_tpm_service_readpublic(TPM_20_SRK_HANDLE, srk_context, srk_context_size,
			               TSS, &handle->srk_pub, &handle->srk_pub_size);
    }
    return result;
}

static HSM_CLIENT_HANDLE hsm_client_tpm_create()
{
    HSM_CLIENT_INFO* result;
    result = malloc(sizeof(HSM_CLIENT_INFO));
    if (result == NULL)
    {
        LOG_ERROR("Failure: malloc HSM_CLIENT_INFO.");
    }
    else
    {
        memset(result, 0, sizeof(HSM_CLIENT_INFO));
        if (initialize_tpm_device(result) != 0)
        {
            LOG_ERROR("Failure initializing tpm device.");
            free(result);
            result = NULL;
        }
    }
    return (HSM_CLIENT_HANDLE)result;
}

static void hsm_client_tpm_destroy(HSM_CLIENT_HANDLE handle)
{
    if (handle != NULL)
    {
        HSM_CLIENT_INFO* hsm_client_info = (HSM_CLIENT_INFO*)handle;
        free(hsm_client_info);
    }
}

static int hsm_client_tpm_activate_identity_key
(
    HSM_CLIENT_HANDLE handle,
    const unsigned char* key,
    size_t key_len
)
{
    int result;
    if (handle == NULL || key == NULL || key_len == 0)
    {
        LOG_ERROR("Invalid argument specified handle: %p, key: %p, key_len: %zu", handle, key, key_len);
        result = __FAILURE__;
    }
    else
    {
        if (insert_key_in_tpm(key, key_len))
        {
            LOG_ERROR("Failure inserting key into tpm");
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

static int hsm_client_tpm_get_endorsement_key
(
    HSM_CLIENT_HANDLE handle,
    unsigned char** key,
    size_t* key_len
)
{
    int result;
    if (handle == NULL || key == NULL || key_len == NULL)
    {
        LOG_ERROR("Invalid handle value specified: handle: %p, result: %p, result_len: %p", handle, key, key_len);
        result = __FAILURE__;
    }
    else
    {
	HSM_CLIENT_INFO *client_info = (HSM_CLIENT_INFO *)handle;
	*key = (unsigned char *)malloc(client_info->ek_pub_size);
        if (*key == NULL) {
		return -1;
	}	
	memcpy(*key, client_info->ek_pub, client_info->ek_pub_size);
	*key_len = client_info->ek_pub_size;
    }
    return result;
}

static int hsm_client_tpm_get_storage_key
(
    HSM_CLIENT_HANDLE handle,
    unsigned char** key,
    size_t* key_len
)
{
    int result;
    if (handle == NULL || key == NULL || key_len == NULL)
    {
        LOG_ERROR("Invalid handle value specified: handle: %p, result: %p, result_len: %p", handle, key, key_len);
        result = __FAILURE__;
    }
    else
    {
	HSM_CLIENT_INFO *client_info = (HSM_CLIENT_INFO *)handle;
	*key = (unsigned char *)malloc(client_info->srk_pub_size);
        if (*key == NULL) {
		return -1;
	}	
	memcpy(*key, client_info->srk_pub, client_info->srk_pub_size);
	*key_len = client_info->srk_pub_size;
    }
    return result;
}

static int hsm_client_tpm_sign_data
(
    HSM_CLIENT_HANDLE handle,
    const unsigned char* data_to_be_signed,
    size_t data_to_be_signed_size,
    unsigned char** digest,
    size_t* digest_size
)
{
    int result = 0;

    if (handle == NULL || data_to_be_signed == NULL || data_to_be_signed_size == 0 ||
                    digest == NULL || digest_size == NULL)
    {
        LOG_ERROR("Invalid handle value specified handle: %p, data: %p, data_size: %zu,"
			" digest: %p, digest_size: %p",
                         handle, data_to_be_signed, data_to_be_signed_size, digest, digest_size);
        result = __FAILURE__;
    }

    eve_tpm_service_hmac(DPS_ID_KEY_HANDLE, EVE_SHA256,
		    data_to_be_signed, data_to_be_signed_size,
		    digest, digest_size);

    return result;
}

static int hsm_client_tpm_derive_and_sign_with_identity
(
   HSM_CLIENT_HANDLE handle,
   const unsigned char* data_to_be_signed,
   size_t data_to_be_signed_size,
   const unsigned char* identity,
   size_t identity_size,
   unsigned char** digest,
   size_t* digest_size
)
{
    return __FAILURE__;
}

static void hsm_client_tpm_free_buffer(void* buffer)
{
    if (buffer != NULL)
    {
        free(buffer);
    }
}

int hsm_client_tpm_device_init(void)
{
    log_init(LVL_INFO);

    return 0;
}

void hsm_client_tpm_device_deinit(void)
{
}

static const HSM_CLIENT_TPM_INTERFACE tpm_interface =
{
    hsm_client_tpm_create,
    hsm_client_tpm_destroy,
    hsm_client_tpm_activate_identity_key,
    hsm_client_tpm_get_endorsement_key,
    hsm_client_tpm_get_storage_key,
    hsm_client_tpm_sign_data,
    hsm_client_tpm_derive_and_sign_with_identity,
    hsm_client_tpm_free_buffer
};

const HSM_CLIENT_TPM_INTERFACE* hsm_client_tpm_device_interface(void)
{
    return &tpm_interface;
}


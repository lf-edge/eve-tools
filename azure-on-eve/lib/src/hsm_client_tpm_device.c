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


#define EPOCH_TIME_T_VALUE          0
#define HMAC_LENGTH                 32
#define TPM_DATA_LENGTH             1024

#if 0
static TPM2B_AUTH      NullAuth = { .t = {0,  {0}} };
#endif 
static TSS_SESSION     NullPwSession;
#if 0
static const UINT32 TPM_20_SRK_HANDLE = HR_PERSISTENT | 0x00000001;
static const UINT32 TPM_20_EK_HANDLE = HR_PERSISTENT | 0x00010001;
static const UINT32 DPS_ID_KEY_HANDLE = HR_PERSISTENT | 0x00000100;
#endif 
#define SRK_PUB_FILE "/home/ubuntu/hsm/srk.pub"
#define EK_PUB_FILE "/home/ubuntu/hsm/ek.pub"

typedef struct HSM_CLIENT_INFO_TAG
{
    TSS_DEVICE tpm_device;
    TPM2B_PUBLIC ek_pub;
    TPM2B_PUBLIC srk_pub;

    TPM2B_PUBLIC id_key_public;
    TPM2B_PRIVATE id_key_dup_blob;
    TPM2B_PRIVATE id_key_priv;
} HSM_CLIENT_INFO;


static inline void
log_error(const char *str) 
{
	FILE *fp = fopen("/tmp/iotege.log", "a");
	fprintf(fp, "%s\n", str); 
	fclose(fp);
}
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
    DPS_UNMARSHAL(UINT32, &(arrSize));                                          \
    printf("act_size %d < actSize %d\r\n", act_size, arrSize);   \
    if (act_size < arrSize)                                                     \
    {                                                                           \
        LOG_ERROR("Unmarshaling " #dstPtr " failed: Need %d bytes, while only %d left", arrSize, act_size);  \
        result = __FAILURE__;       \
    }                                                                           \
    else                            \
    {                                   \
        dstPtr = curr_pos - sizeof(UINT16);                                         \
        *(UINT16*)dstPtr = (UINT16)arrSize;                                         \
        curr_pos += arrSize;                         \
    }

static int
write_buf_to_file (const char *buf, int buflen, const char *filename)
{
	FILE *fp = fopen(filename, "wb");
	log_error(__FUNCTION__);
	if (!fp) {
		return -1;
	}
	fwrite(buf, buflen, 1, fp);
	fclose(fp);
	return 0;
}

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
    	log_error(__FUNCTION__);
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
/**
 * Writes size bytes to a file, continuing on EINTR short writes.
 * @param f
 *  The file to write to.
 * @param data
 *  The data to write.
 * @param size
 *  The size, in bytes, of that data.
 * @return
 *  True on success, False otherwise.
 */
static bool writex(FILE *f, UINT8 *data, size_t size) {

    size_t wrote = 0;
    size_t index = 0;
    do {
        wrote = fwrite(&data[index], 1, size, f);
        if (wrote != size) {
            if (errno != EINTR) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= wrote;
        index += wrote;
    } while (size > 0);

    return true;
}

#if 0
/**
 * Reads size bytes from a file, continuing on EINTR short reads.
 * @param f
 *  The file to read from.
 * @param data
 *  The data buffer to read into.
 * @param size
 *  The size of the buffer, which is also the amount of bytes to read.
 * @return
 *  True on success, False otherwise.
 */
static bool readx(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    size_t index = 0;
    do {
        bread = fread(&data[index], 1, size, f);
        if (bread != size) {
            if (feof(f) || (errno != EINTR)) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= bread;
        index += bread;
    } while (size > 0);

    return true;
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
//STRING_BYTES_ENDIAN_CONVERT(64)

#define BE_CONVERT(value, size) \
    do { \
        if (!tpm2_util_is_big_endian()) { \
            value = tpm2_util_endian_swap_##size(value); \
        } \
    } while (0)

#define FILE_WRITE(size) \
    bool files_write_##size(FILE *out, UINT##size data) { \
        BAIL_ON_NULL("FILE", out); \
        BE_CONVERT(data, size); \
        return writex(out, (UINT8 *)&data, sizeof(data)); \
    }


#define FILE_READ(size) \
    bool files_read_##size(FILE *out, UINT##size *data) { \
            BAIL_ON_NULL("FILE", out); \
            BAIL_ON_NULL("data", data); \
        bool res = readx(out, (UINT8 *)data, sizeof(*data)); \
        if (res) { \
            BE_CONVERT(*data, size); \
        } \
        return res; \
    }

/**
 * This is the magic for the file header. The header is organized
 * as a big endian U32 (BEU32) of MAGIC followed by a BEU32 of the
 * version number. Tools can define their own, individual file
 * formats as they make sense, but they should always have the header.
 */
static const UINT32 MAGIC = 0xBADCC0DE;

#define BAIL_ON_NULL(param, x) \
    do { \
        if (!x) { \
            LOG_ERROR(param" must be specified"); \
            return false; \
        } \
    } while(0)

/*
 * all the files_read|write_bytes_16|32|64 functions
 */
//FILE_READ(16);
FILE_WRITE(16)

//FILE_READ(32);
FILE_WRITE(32)

//FILE_READ(64)
//FILE_WRITE(64)

#if 0
bool files_read_bytes(FILE *out, UINT8 bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return readx(out, bytes, len);
}
#endif 

static bool files_write_bytes(FILE *out, uint8_t bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return writex(out, bytes, len);
}

static bool files_write_header(FILE *out, UINT32 version) {

    BAIL_ON_NULL("FILE", out);

    bool res = files_write_32(out, MAGIC);
    if (!res) {
        return false;
    }
    return files_write_32(out, version);
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

    	log_error(__FUNCTION__);
	
	uint8_t buf[4096];
	uint8_t *pBuf = buf;
	uint16_t buflen = 0;
	size_t max_len = 4096;
	DPS_MARSHAL(TPM2B_PRIVATE, &id_key_dup_blob, pBuf, max_len);
	write_buf_to_file((char *)buf, buflen, "id_key_dup_blob.out");
	pBuf = buf, max_len = 4096;
	DPS_MARSHAL(TPM2B_ENCRYPTED_SECRET, &encrypt_wrap_key, pBuf, max_len);
	write_buf_to_file((char *)buf, buflen, "encrypt_wrap_key.out");

	pBuf = buf, max_len = 4096;
	DPS_MARSHAL(TPM2B_ENCRYPTED_SECRET, &tpm_enc_secret, pBuf, max_len);
	write_buf_to_file((char *)buf, buflen, "tpm_enc_secret.out");
	pBuf = buf, max_len = 4096;
	DPS_MARSHAL(TPM2B_PUBLIC, &id_key_Public, pBuf, max_len);
	write_buf_to_file((char *)buf, buflen, "id_key_Public.out");

	FILE *cred_blob_file = fopen("cred_blob.in", "w");
	if (!cred_blob_file) {
		log_error("failed to open file to write cred_blob.in");
	} else {
		log_error("Opened file to write cred_blob.in");
	}
	files_write_header(cred_blob_file, 1);
	files_write_16(cred_blob_file, enc_key_blob.t.size);
	files_write_bytes(cred_blob_file, enc_key_blob.t.credential, enc_key_blob.t.size); 
	files_write_16(cred_blob_file, tpm_enc_secret.t.size);
	files_write_bytes(cred_blob_file, tpm_enc_secret.t.secret, tpm_enc_secret.t.size);
	fclose(cred_blob_file);

	system("eve_run tpm2_startauthsession --policy-session -S session.ctx");
	system("eve_run tpm2_policysecret -S session.ctx -c 0x4000000B");
	system("eve_run tpm2_activatecredential -c 0x81000001 -C 0x81010001 -i cred_blob.in -o inner_wrap_key.out -P '\"session:session.ctx\"'");
	system("eve_run tpm2_flushcontext session.ctx");

	system("eve_run tpm2_startauthsession --policy-session -S session.ctx");
	system("eve_run tpm2_policysecret -S session.ctx -c 0x4000000B");
	system("eve_run tpm2_import -C 0x81000001 -k inner_wrap_key.out -u id_key_Public.out -r id_key_priv.in -i id_key_dup_blob.out -s encrypt_wrap_key.out -L dpolicy.dat");
	system("eve_run tpm2_flushcontext session.ctx");
	system("eve_run tpm2_load -C 0x81000001 -u id_key_Public.out -r id_key_priv.in -c id_key_context.out");
	system("eve_run tpm2_evictcontrol -c 0x81000100");
	system("eve_run tpm2_evictcontrol -c id_key_context.out 0x81000100");

	return result;
}

static int exists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

static int initialize_tpm_device()
{
    int result = 0;
    log_error("Initializing TPM device");
    system("pwd > /tmp/pwd.log");
    if (!exists(EK_PUB_FILE)) {
	    system("eve_run tpm2_createek -c 0x81010001 -G rsa -u ek.pub -f tss");
    } 
    if (!exists(SRK_PUB_FILE)) {
	    system("eve_run tpm2_createprimary -C e -G rsa -g sha256 -c context.out -a \"'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth'\"");
	    system("eve_run tpm2_evictcontrol -c context.out 0x81000001");
	    system("eve_run tpm2_readpublic -c context.out -o srk.pub -f tss");
    }
    return result;
}

static HSM_CLIENT_HANDLE hsm_client_tpm_create()
{
    HSM_CLIENT_INFO* result;
    result = malloc(sizeof(HSM_CLIENT_INFO) );
    if (result == NULL)
    {
        LOG_ERROR("Failure: malloc HSM_CLIENT_INFO.");
    }
    else
    {
        memset(result, 0, sizeof(HSM_CLIENT_INFO));
        if (initialize_tpm_device() != 0)
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

        Deinit_TPM_Codec(&hsm_client_info->tpm_device);
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
	result = read_from_file_to_buf(EK_PUB_FILE, key_len, key);
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
	result = read_from_file_to_buf(SRK_PUB_FILE, key_len, key);
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
        LOG_ERROR("Invalid handle value specified handle: %p, data: %p, data_size: %zu, digest: %p, digest_size: %p",
            handle, data_to_be_signed, data_to_be_signed_size, digest, digest_size);
        result = __FAILURE__;
    }
    write_buf_to_file((char *)data_to_be_signed, data_to_be_signed_size, "tok.dat");
    system("eve_run cp -f tok.dat token.dat");
    system("eve_run tpm2_hmac -c 0x81000100 -g sha256 -o hmac.out token.dat");
    read_from_file_to_buf("hmac.out", digest_size, digest); 
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


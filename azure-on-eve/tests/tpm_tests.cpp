
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/// Derived fom azure-iot-sdk-c library.
/// https://github.com/Azure/azure-iot-sdk-c/blob/main/provisioning_client/tests/hsm_client_tpm_ut/hsm_client_tpm_ut.c

#include "microtest.h"
#include "hsm_client_data.h"
#include "azure_utpm_c/BaseTypes.h"
#include "azure_utpm_c/TpmTypes.h"
#include "azure_utpm_c/Marshal_fp.h"

extern HSM_CLIENT_HANDLE hsm_client_tpm_create();
extern void hsm_client_tpm_destroy(HSM_CLIENT_HANDLE handle);
extern int insert_key_in_tpm(HSM_CLIENT_HANDLE, const unsigned char*, size_t);
extern int hsm_client_tpm_get_endorsement_key(HSM_CLIENT_HANDLE, unsigned char**, size_t*);
extern int hsm_client_tpm_get_storage_key(HSM_CLIENT_HANDLE, unsigned char**, size_t*);
extern int hsm_client_tpm_sign_data(HSM_CLIENT_HANDLE, const unsigned char*, size_t, unsigned char**, size_t*);

static const unsigned char TEST_IMPORT_KEY[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10 };
#define TEST_KEY_SIZE sizeof(TEST_IMPORT_KEY)

static unsigned char TEST_BUFFER[128];
#define TEST_BUFFER_SIZE 128

#define MAX_KEY_SIZE 4096

typedef struct HSM_CLIENT_INFO_TAG
{
    uint8_t *ek_pub;
    size_t ek_pub_size;

    uint8_t *srk_pub;
    size_t srk_pub_size;

    uint8_t *dps_key_context;
    size_t dps_key_context_size;

} HSM_CLIENT_INFO;

size_t get_file_size(FILE* fp) {
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return size;
}

int hsm_client_tpm_import_key(HSM_CLIENT_HANDLE handle, const unsigned char* key, size_t key_len)
{
    if (handle == NULL || key == NULL || key_len == 0)
        return 1;
    
    return insert_key_in_tpm(handle, key, key_len);
}

TEST_FUNC(hsm_client_tpm_import_key_succeed)
{
    
    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    BYTE* my_key = (BYTE*)malloc(MAX_KEY_SIZE);
    memset(my_key, 0, MAX_KEY_SIZE);

    FILE* fp = fopen("./insert_key.bin", "r");
    fread(my_key, get_file_size(fp), 1, fp);

    int import_res =  hsm_client_tpm_import_key(sec_handle, my_key, MAX_KEY_SIZE);
    ASSERT_EQ(0, import_res); 

    free(my_key);
    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_create_succeed) {
    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();
    ASSERT_NOTNULL(sec_handle);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_import_key_handle_NULL_fail)
{
    int import_res = hsm_client_tpm_import_key(NULL, TEST_IMPORT_KEY, TEST_KEY_SIZE);
    ASSERT_NEQ(0, import_res);
}

TEST_FUNC(hsm_client_tpm_import_key_key_NULL_fail)
{
    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int import_res = hsm_client_tpm_import_key(sec_handle, NULL, TEST_KEY_SIZE);
    ASSERT_NEQ(0, import_res);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_get_endorsement_key_handle_NULL_succeed)
{
    unsigned char* key;
    size_t key_len;

    int result = hsm_client_tpm_get_endorsement_key(NULL, &key, &key_len);
    ASSERT_NEQ(0, result);
}

TEST_FUNC(hsm_client_tpm_get_endorsement_key_size_0_fail)
{
    unsigned char* key;
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_get_endorsement_key(NULL, &key, &key_len);
    ASSERT_NEQ(0, result);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_get_endorsement_key_succeed)
{
    unsigned char* key;
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_get_endorsement_key(sec_handle, &key, &key_len);
    ASSERT_EQ(0, result);

    if (result)
        free(key);
    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_get_storage_key_handle_NULL_fail)
{
    unsigned char* key;
    size_t key_len;

    int result = hsm_client_tpm_get_storage_key(NULL, &key, &key_len);

    ASSERT_NEQ(0, result);
}

TEST_FUNC(hsm_client_tpm_get_storage_key_size_0_fail)
{
    unsigned char* key;
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_get_storage_key(NULL, &key, &key_len);
    ASSERT_NEQ(0, result);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_get_storage_key_succeed)
{
    unsigned char* key;
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_get_storage_key(sec_handle, &key, &key_len);
    ASSERT_EQ(0, result);

    free(key);
    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_sign_data_handle_fail)
{
    unsigned char* key;
    size_t key_len;

    int result = hsm_client_tpm_sign_data(NULL, TEST_BUFFER, TEST_BUFFER_SIZE, &key, &key_len);
    ASSERT_NEQ(0, result);
}

TEST_FUNC(hsm_client_tpm_sign_data_data_NULL_fail)
{
    unsigned char* key;
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_sign_data(sec_handle, NULL, TEST_BUFFER_SIZE, &key, &key_len);
    ASSERT_NEQ(0, result);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_sign_data_size_0_fail)
{
    unsigned char* key;
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_sign_data(sec_handle, TEST_BUFFER, 0, &key, &key_len);
    ASSERT_NEQ(0, result);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_sign_data_key_NULL_fail)
{
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_sign_data(sec_handle, TEST_BUFFER, TEST_BUFFER_SIZE, NULL, &key_len);
    ASSERT_NEQ(0, result);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_sign_data_keylen_NULL_fail)
{
    unsigned char* key;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();

    int result = hsm_client_tpm_sign_data(sec_handle, TEST_BUFFER, TEST_BUFFER_SIZE, &key, NULL);
    ASSERT_NEQ(0, result);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_sign_data_succeed)
{
    unsigned char* key;
    size_t key_len;

    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();


    FILE* fp = fopen("./hmac.key", "r");
    size_t size = get_file_size(fp);
    uint8_t* hmac = (uint8_t*)malloc(size);
    fread(hmac, size, 1, fp);


    HSM_CLIENT_INFO* client_info = (HSM_CLIENT_INFO*)sec_handle;
    client_info->dps_key_context = hmac;
    client_info->dps_key_context_size = size;

    int result = hsm_client_tpm_sign_data(sec_handle, TEST_BUFFER, TEST_BUFFER_SIZE, &key, &key_len);
    ASSERT_EQ(0, result);

    free(key);
    free(hmac);
    hsm_client_tpm_destroy(sec_handle);
}

TEST_FUNC(hsm_client_tpm_interface_succeed)
{
    HSM_CLIENT_HANDLE sec_handle = hsm_client_tpm_create();
    const HSM_CLIENT_TPM_INTERFACE* tpm_iface = hsm_client_tpm_interface();

    ASSERT_NOTNULL(tpm_iface);
    ASSERT_NOTNULL(tpm_iface->hsm_client_tpm_create);
    ASSERT_NOTNULL(tpm_iface->hsm_client_tpm_destroy);
    ASSERT_NOTNULL(tpm_iface->hsm_client_get_ek);
    ASSERT_NOTNULL(tpm_iface->hsm_client_get_srk);
    ASSERT_NOTNULL(tpm_iface->hsm_client_activate_identity_key);
    ASSERT_NOTNULL(tpm_iface->hsm_client_sign_with_identity);

    hsm_client_tpm_destroy(sec_handle);
}

TEST_MAIN();

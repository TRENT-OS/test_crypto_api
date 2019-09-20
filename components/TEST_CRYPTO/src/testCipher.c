/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoCipher.h"
#include "SeosCryptoApi.h"

#include <string.h>

static void
testCipher_AES_ECB_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    SeosCrypto_KeyHandle keyHandle;
    SeosCrypto_CipherHandle handle;
    SeosCryptoKey_AES keyData =
    {
        "0123456789ABCDEF", 16
    };
    const char*  data   = "0123456789ABCDEF";
    size_t dataLen      = strlen(data);

    char buff[16];
    void* output = buff;
    size_t outputSize = sizeof(buff);

    err = SeosCryptoApi_keyInit(ctx, &keyHandle, SeosCryptoKey_Type_AES, 0,
                                128);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyImport(ctx, keyHandle, NULL, &keyData,
                                  sizeof(keyData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_cipherInit(ctx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC,
                                   keyHandle,
                                   NULL, 0);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    err = SeosCryptoApi_cipherUpdate(ctx,
                                     handle,
                                     data,
                                     dataLen,
                                     &output,
                                     &outputSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    Debug_ASSERT(outputSize == dataLen);

    Debug_PRINTF("Printing AES-ECB encrypted data ...");
    for (unsigned j = 0; j < outputSize; j++)
    {
        Debug_PRINTF(" 0x%02x", ((char*) output)[j]);
    }
    Debug_PRINTF("\n");

    err = SeosCryptoApi_cipherClose(ctx, handle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    err = SeosCryptoApi_cipherInit(ctx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC,
                                   keyHandle,
                                   NULL, 0);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    data    = output;
    dataLen = outputSize;
    output  = NULL;

    err = SeosCryptoApi_cipherUpdate(ctx,
                                     handle,
                                     data,
                                     dataLen,
                                     &output,
                                     &outputSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    Debug_PRINTF("Printing AES-ECB decrypted data ...");
    for (unsigned j = 0; j < outputSize; j++)
    {
        Debug_PRINTF(" 0x%02x", ((char*) output)[j]);
    }
    Debug_PRINTF("\n");

    // Just for fun call also finalize; currently this won't do anything for
    // ECB mode but it should also not harm.
    output = NULL;
    outputSize = 0;
    err = SeosCryptoApi_cipherFinalize(ctx,
                                       handle,
                                       &output, &outputSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    Debug_ASSERT(outputSize == 0);

    err = SeosCryptoApi_cipherClose(ctx, handle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    SeosCryptoApi_keyDeInit(ctx, keyHandle);
}

static void
testCipher_AES_GCM_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    SeosCrypto_KeyHandle keyHandle;
    SeosCrypto_CipherHandle handle;
    SeosCryptoKey_AES keyData =
    {
        "0123456789ABCDEF", 16
    };

    const char* iv     = "0000000000000000";
    const char* data1  = "FFFFFFFFFFFFFFFF";
    const char* data2  = "00000000000000";
    const char* ad     = "0123";
    size_t data1Len    = strlen(data1);
    size_t data2Len    = strlen(data2);
    size_t ivLen       = strlen(iv);
    size_t adLen       = strlen(ad);
    char tag_buf[16];
    char enc_out_buf[64];
    char dec_out_buf[64];
    size_t tagSize     = sizeof(tag_buf);
    size_t decOutputSize = sizeof(dec_out_buf);
    size_t encOutputSize = sizeof(enc_out_buf);
    void* decOutput    = dec_out_buf;
    void* encOutput    = enc_out_buf;
    void* tag          = tag_buf;

    err = SeosCryptoApi_keyInit(ctx, &keyHandle, SeosCryptoKey_Type_AES, 0,
                                128);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyImport(ctx, keyHandle, NULL, &keyData,
                                  sizeof(keyData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    //
    // Encrypt some data
    //

    err = SeosCryptoApi_cipherInit(ctx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC,
                                   keyHandle,
                                   iv, ivLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    err = SeosCryptoApi_cipherUpdateAd(ctx,
                                       handle,
                                       ad, adLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    // Encrypt first block
    err = SeosCryptoApi_cipherUpdate(ctx,
                                     handle,
                                     data1, data1Len,
                                     &encOutput,  &encOutputSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    Debug_ASSERT(encOutputSize == data1Len);

    // Encrypt second block
    encOutput      += encOutputSize;
    encOutputSize   = sizeof(enc_out_buf) - encOutputSize;
    err = SeosCryptoApi_cipherUpdate(ctx,
                                     handle,
                                     data2, data2Len,
                                     &encOutput,  &encOutputSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    Debug_ASSERT(encOutputSize == data2Len);

    Debug_PRINTF("Printing AES-GCM encrypted data ...");
    for (unsigned j = 0; j < data1Len + data2Len; j++)
    {
        Debug_PRINTF(" 0x%02x", enc_out_buf[j]);
    }
    Debug_PRINTF("\n");

    err = SeosCryptoApi_cipherFinalize(ctx,
                                       handle,
                                       &tag, &tagSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    Debug_PRINTF("Printing AES-GCM tag ...");
    for (unsigned j = 0; j < tagSize; j++)
    {
        Debug_PRINTF(" 0x%02x", ((unsigned char*) tag)[j]);
    }
    Debug_PRINTF("\n");

    err = SeosCryptoApi_cipherClose(ctx, handle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    //
    // Decrypt all again
    //

    err = SeosCryptoApi_cipherInit(ctx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_DEC,
                                   keyHandle,
                                   (void*)iv, ivLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    err = SeosCryptoApi_cipherUpdateAd(ctx,
                                       handle,
                                       ad, adLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    // Decrypt all the data in one call
    encOutput = enc_out_buf;
    encOutputSize = data1Len + data2Len;
    err = SeosCryptoApi_cipherUpdate(ctx,
                                     handle,
                                     encOutput, encOutputSize,
                                     &decOutput,  &decOutputSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    Debug_ASSERT(decOutputSize == encOutputSize);

    Debug_PRINTF("Printing AES-GCM decrypted data ...");
    for (unsigned j = 0; j < decOutputSize; j++)
    {
        Debug_PRINTF(" 0x%02x", ((unsigned char*) decOutput)[j]);
    }
    Debug_PRINTF("\n");

    err = SeosCryptoApi_cipherVerifyTag(ctx,
                                        handle,
                                        tag, tagSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    err = SeosCryptoApi_cipherClose(ctx, handle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    SeosCryptoApi_keyDeInit(ctx, keyHandle);
}

void
testCipher(SeosCryptoCtx* ctx)
{
    testCipher_AES_GCM_ok(ctx);
    testCipher_AES_ECB_ok(ctx);
}
/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoDigest.h"
#include "SeosCryptoApi.h"

#include <string.h>

static
void testDigest_update_MD5_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    SeosCrypto_DigestHandle handle;

    err = SeosCryptoApi_digestInit(ctx,
                                   &handle,
                                   SeosCryptoDigest_Algorithm_MD5,
                                   NULL,
                                   0);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    const char* data        = "0123456789";
    const size_t dataLen    = strlen(data);
    char buff[SeosCryptoDigest_SIZE_MD5];
    void*  digest = buff;
    size_t digestSize = sizeof(buff);
    err = SeosCryptoApi_digestFinalize(ctx,
                                       handle,
                                       data,
                                       dataLen,
                                       &digest,
                                       &digestSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    Debug_PRINTF("Printing MD5 digest...");
    for (unsigned j = 0; j < digestSize; j++)
    {
        Debug_PRINTF(" 0x%02x", buff[j]);
    }
    Debug_PRINTF("\n");

    err = SeosCryptoApi_digestClose(ctx, handle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
}

static
void testDigest_update_SHA256_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    SeosCrypto_DigestHandle handle;

    err = SeosCryptoApi_digestInit(ctx,
                                   &handle,
                                   SeosCryptoDigest_Algorithm_SHA256,
                                   NULL,
                                   0);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    const char* data = "0123456789";
    size_t dataLen = strlen(data);

    err = SeosCryptoApi_digestUpdate(ctx,
                                     handle,
                                     data,
                                     dataLen);

    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    void*   digest      = NULL;
    size_t  digestSize  = 0;
    err = SeosCryptoApi_digestFinalize(ctx,
                                       handle,
                                       NULL, 0,
                                       &digest, &digestSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    Debug_PRINTF("Printing SHA256 digest...");
    for (unsigned j = 0; j < digestSize; j++)
    {
        Debug_PRINTF(" 0x%02x", ((char*) digest)[j]);
    }
    Debug_PRINTF("\n");

    err = SeosCryptoApi_digestClose(ctx, handle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
}

void
testDigest(SeosCryptoCtx* ctx)
{
    testDigest_update_SHA256_ok(ctx);
    testDigest_update_MD5_ok(ctx);
}
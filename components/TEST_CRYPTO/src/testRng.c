/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoRng.h"
#include "SeosCryptoApi.h"

#include <string.h>

static void testRng_getBytes_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char data[16];

    err = SeosCryptoApi_rngGetBytes(ctx,  0, data, sizeof(data));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void testRng_getBytes_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char data[16];

    // Empty context
    err = SeosCryptoApi_rngGetBytes(NULL, 0, data, sizeof(data));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    // Invalid flag
    err = SeosCryptoApi_rngGetBytes(ctx, 666, data, sizeof(data));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_SUPPORTED, "err %d", err);

    // Empty buffer
    err = SeosCryptoApi_rngGetBytes(ctx, 0, NULL, sizeof(data));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    // Zero-length buffer
    err = SeosCryptoApi_rngGetBytes(ctx, 0, data, 0);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void testRng_reSeed_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    err = SeosCryptoApi_rngReSeed(ctx, seed, sizeof(seed));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void testRng_reSeed_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    err = SeosCryptoApi_rngReSeed(NULL, seed, sizeof(seed));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    err = SeosCryptoApi_rngReSeed(ctx, NULL, sizeof(seed));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    err = SeosCryptoApi_rngReSeed(ctx, seed, 0);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void testRng(SeosCryptoCtx* ctx)
{
    testRng_getBytes_ok(ctx);
    testRng_getBytes_fail(ctx);

    testRng_reSeed_ok(ctx);
    testRng_reSeed_fail(ctx);
}
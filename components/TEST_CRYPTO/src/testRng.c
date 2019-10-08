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
    void* rnd = data;

    for (int i = 0; i < 3; i++)
    {
        err = SeosCryptoApi_rngGetBytes(ctx, &rnd, sizeof(data));
        Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

        Debug_PRINTF("Printing random bytes...");
        for (unsigned j = 0; j < sizeof(data); j++)
        {
            Debug_PRINTF(" 0x%02x", data[j]);
        }
        Debug_PRINTF("\n");
    }
}

void testRng(SeosCryptoCtx* ctx)
{
    testRng_getBytes_ok(ctx);
}
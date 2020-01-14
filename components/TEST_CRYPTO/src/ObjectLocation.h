/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

#include "Crypto.h"
#include "LibDebug/Debug.h"

#define Debug_ASSERT_OBJ_LOCAL(o) \
    Debug_ASSERT_PRINTFLN(!Crypto_hasObject(o), "Object at 0x%lx is not local", (long) o)

#define Debug_ASSERT_OBJ_REMOTE(o) \
    Debug_ASSERT_PRINTFLN(Crypto_hasObject(o), "Object at 0x%lx is not remote", (long) o)

#define Debug_ASSERT_OBJ_LOCATION(api, isLocal, o)              \
    if(api->mode == SeosCryptoApi_Mode_LIBRARY ||               \
       (api->mode == SeosCryptoApi_Mode_ROUTER && isLocal)) {   \
        Debug_ASSERT_OBJ_LOCAL(o);                              \
    } else if(api->mode == SeosCryptoApi_Mode_RPC_CLIENT ||     \
       (api->mode == SeosCryptoApi_Mode_ROUTER && !isLocal)) {  \
        Debug_ASSERT_OBJ_REMOTE(o);                             \
    } else {                                                    \
        Debug_ASSERT_PRINTFLN(1 == 0, "Cannot assert location");\
    }

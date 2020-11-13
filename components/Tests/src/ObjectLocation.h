/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

#include "LibMacros/Test.h"

#include <camkes.h>

// Test location of object pointer based on location
#define TEST_LOCACTION_FLAG(m, l, o) do {               \
    intptr_t p = (intptr_t) OS_Crypto_getProxyPtr(o);   \
    if(m == OS_Crypto_MODE_LIBRARY ||                   \
       (m == OS_Crypto_MODE_KEY_SWITCH && l)) {         \
        TEST_TRUE(!testServer_rpc_hasObject(p));        \
    } else if(m == OS_Crypto_MODE_CLIENT ||             \
              (m == OS_Crypto_MODE_KEY_SWITCH && !l)) { \
        TEST_TRUE(testServer_rpc_hasObject(p));         \
    }                                                   \
} while(0)

// Test location of object pointer based on api mode only (used with objects
// which have no key attached and are thus independent of key's locality)
#define TEST_LOCACTION(m, o) do {                       \
    intptr_t p = (intptr_t) OS_Crypto_getProxyPtr(o);   \
    if(m == OS_Crypto_MODE_LIBRARY ||                   \
       (m == OS_Crypto_MODE_KEY_SWITCH)) {              \
        TEST_TRUE(!testServer_rpc_hasObject(p));        \
    } else {                                            \
        TEST_TRUE(testServer_rpc_hasObject(p));         \
    }                                                   \
} while(0)

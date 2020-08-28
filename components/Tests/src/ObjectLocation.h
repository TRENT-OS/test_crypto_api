/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"
#include "TestMacros.h"

#include <camkes.h>

// Test location of object pointer based on exportable flag and api mode
#define TEST_LOCACTION_EXP(m, e, o) {                   \
    intptr_t p = (intptr_t) OS_Crypto_getProxyPtr(o);   \
    if(m == OS_Crypto_MODE_LIBRARY_ONLY ||              \
       (m == OS_Crypto_MODE_CLIENT && e)) {             \
        TEST_TRUE(!testServer_rpc_hasObject(p));        \
    } else if(m == OS_Crypto_MODE_CLIENT_ONLY ||        \
              (m == OS_Crypto_MODE_CLIENT && !e)) {     \
        TEST_TRUE(testServer_rpc_hasObject(p));         \
    }                                                   \
}

// Test location of object pointer based on api mode only (used with objects
// which have no key attached and are thus independent of their exportability)
#define TEST_LOCACTION(m, o) {                          \
    intptr_t p = (intptr_t) OS_Crypto_getProxyPtr(o);   \
    if(m == OS_Crypto_MODE_LIBRARY_ONLY ||              \
       (m == OS_Crypto_MODE_CLIENT)) {                  \
        TEST_TRUE(!testServer_rpc_hasObject(p));        \
    } else {                                            \
        TEST_TRUE(testServer_rpc_hasObject(p));         \
    }                                                   \
}

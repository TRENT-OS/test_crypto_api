/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

OS_Error_t
CryptoRpcServer_openSession();

int
CryptoRpcServer_hasObject(
    CryptoLib_Object_ptr ptr);

OS_Error_t
CryptoRpcServer_loadKey(
    CryptoLib_Object_ptr* ptr);

OS_Error_t
CryptoRpcServer_closeSession();
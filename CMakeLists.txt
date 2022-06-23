#
# Test Crypto API
#
# Copyright (C) 2019-2022, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# use the SDK
find_package("os-sdk" REQUIRED)
os_sdk_set_defaults()
os_sdk_setup(CONFIG_FILE "config.h" CONFIG_PROJECT "system_config")


#-------------------------------------------------------------------------------
project(tests_crypto_api C)

DeclareCAmkESComponent(
    test_OS_Crypto
    SOURCES
        components/Tests/src/test_OS_Crypto.c
        components/Tests/src/test_OS_CryptoSignature.c
        components/Tests/src/test_OS_CryptoCipher.c
        components/Tests/src/test_OS_CryptoRng.c
        components/Tests/src/test_OS_CryptoDigest.c
        components/Tests/src/test_OS_CryptoMac.c
        components/Tests/src/test_OS_CryptoAgreement.c
        components/Tests/src/test_OS_CryptoKey.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        lib_compiler
        lib_macros
        os_crypto
)

DeclareCAmkESComponent(
    TestServer
    SOURCES
        components/TestServer/src/testServer_rpc.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        lib_debug
        lib_utils
        os_crypto
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

os_sdk_create_CAmkES_system("main.camkes")

cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CRYPTO_WITH_RPC_CLIENT
    SEOS_CRYPTO_WITH_RPC_SERVER
    SEOS_CRYPTO_IMPL_MBEDTLS
)

project(tests_crypto_api C)

DeclareCAmkESComponent(TEST_CRYPTO
    INCLUDES
        common
        components/CRYPTO/instance
    SOURCES
        components/TEST_CRYPTO/src/test_SeosCryptoApi.c
        components/TEST_CRYPTO/src/test_SeosCryptoApi_Signature.c
        components/TEST_CRYPTO/src/test_SeosCryptoApi_Cipher.c
        components/TEST_CRYPTO/src/test_SeosCryptoApi_Rng.c
        components/TEST_CRYPTO/src/test_SeosCryptoApi_Digest.c
        components/TEST_CRYPTO/src/test_SeosCryptoApi_Mac.c
        components/TEST_CRYPTO/src/test_SeosCryptoApi_Agreement.c
        components/TEST_CRYPTO/src/test_SeosCryptoApi_Key.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(CRYPTO
    INCLUDES
        common
        components/CRYPTO/instance
    SOURCES
        components/CRYPTO/instance/Crypto.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_server
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()

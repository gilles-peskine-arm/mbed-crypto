/**
 * \file psa/crypto_compat.h
 *
 * \brief PSA cryptography module: Backward compatibility aliases
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 */
/*
 *  Copyright (C) 2019, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef PSA_CRYPTO_COMPAT_H
#define PSA_CRYPTO_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

#if defined(MBEDTLS_DEPRECATED_WARNING) && !defined(MBEDTLS_PSA_DEPRECATED)
#define MBEDTLS_PSA_DEPRECATED __attribute__((deprecated))
#else
#define MBEDTLS_PSA_DEPRECATED
#endif

typedef MBEDTLS_PSA_DEPRECATED psa_status_t mbedtls_deprecated_psa_status_t;

#define MBEDTLS_DEPRECATED_CONSTANT( type, value )      \
    ( (mbedtls_deprecated_##type) ( value ) )

/*
 * Deprecated PSA Crypto error code definitions
 */
#define PSA_ERROR_UNKNOWN_ERROR \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_GENERIC_ERROR )
#define PSA_ERROR_OCCUPIED_SLOT \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_ALREADY_EXISTS )
#define PSA_ERROR_EMPTY_SLOT \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_DOES_NOT_EXIST )
#define PSA_ERROR_INSUFFICIENT_CAPACITY \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_INSUFFICIENT_DATA )
#define PSA_ERROR_TAMPERING_DETECTED \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_CORRUPTION_DETECTED )

#endif /* MBEDTLS_DEPRECATED_REMOVED */

/*
 * Size-specific elliptic curve and Diffie-Hellman group names
 */
#define PSA_ECC_CURVE_SECP160K1         ((psa_ecc_curve_t) 0x1600a0)
#define PSA_ECC_CURVE_SECP192K1         ((psa_ecc_curve_t) 0x1600c0)
#define PSA_ECC_CURVE_SECP224K1         ((psa_ecc_curve_t) 0x1600e0)
#define PSA_ECC_CURVE_SECP256K1         ((psa_ecc_curve_t) 0x160100)
#define PSA_ECC_CURVE_SECP160R1         ((psa_ecc_curve_t) 0x1200a0)
#define PSA_ECC_CURVE_SECP192R1         ((psa_ecc_curve_t) 0x1200c0)
#define PSA_ECC_CURVE_SECP224R1         ((psa_ecc_curve_t) 0x1200e0)
#define PSA_ECC_CURVE_SECP256R1         ((psa_ecc_curve_t) 0x120100)
#define PSA_ECC_CURVE_SECP384R1         ((psa_ecc_curve_t) 0x120180)
#define PSA_ECC_CURVE_SECP521R1         ((psa_ecc_curve_t) 0x120209)
#define PSA_ECC_CURVE_SECP160R2         ((psa_ecc_curve_t) 0x1a00a0)
#define PSA_ECC_CURVE_SECT163K1         ((psa_ecc_curve_t) 0x2600a3)
#define PSA_ECC_CURVE_SECT233K1         ((psa_ecc_curve_t) 0x2600e9)
#define PSA_ECC_CURVE_SECT239K1         ((psa_ecc_curve_t) 0x2600ef)
#define PSA_ECC_CURVE_SECT283K1         ((psa_ecc_curve_t) 0x26011b)
#define PSA_ECC_CURVE_SECT409K1         ((psa_ecc_curve_t) 0x260199)
#define PSA_ECC_CURVE_SECT571K1         ((psa_ecc_curve_t) 0x26023b)
#define PSA_ECC_CURVE_SECT163R1         ((psa_ecc_curve_t) 0x2200a3)
#define PSA_ECC_CURVE_SECT193R1         ((psa_ecc_curve_t) 0x2200c1)
#define PSA_ECC_CURVE_SECT233R1         ((psa_ecc_curve_t) 0x2200e9)
#define PSA_ECC_CURVE_SECT283R1         ((psa_ecc_curve_t) 0x22011b)
#define PSA_ECC_CURVE_SECT409R1         ((psa_ecc_curve_t) 0x220199)
#define PSA_ECC_CURVE_SECT571R1         ((psa_ecc_curve_t) 0x22023b)
#define PSA_ECC_CURVE_SECT163R2         ((psa_ecc_curve_t) 0x2a00a3)
#define PSA_ECC_CURVE_SECT193R2         ((psa_ecc_curve_t) 0x2a00c1)
#define PSA_ECC_CURVE_BRAINPOOL_P256R1  ((psa_ecc_curve_t) 0x300100)
#define PSA_ECC_CURVE_BRAINPOOL_P384R1  ((psa_ecc_curve_t) 0x300180)
#define PSA_ECC_CURVE_BRAINPOOL_P512R1  ((psa_ecc_curve_t) 0x300200)
#define PSA_ECC_CURVE_CURVE25519        ((psa_ecc_curve_t) 0x0200ff)
#define PSA_ECC_CURVE_CURVE448          ((psa_ecc_curve_t) 0x0201c0)

#define PSA_DH_GROUP_FFDHE2048          ((psa_dh_group_t) 0x020800)
#define PSA_DH_GROUP_FFDHE3072          ((psa_dh_group_t) 0x020c00)
#define PSA_DH_GROUP_FFDHE4096          ((psa_dh_group_t) 0x021000)
#define PSA_DH_GROUP_FFDHE6144          ((psa_dh_group_t) 0x021800)
#define PSA_DH_GROUP_FFDHE8192          ((psa_dh_group_t) 0x022000)

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_COMPAT_H */

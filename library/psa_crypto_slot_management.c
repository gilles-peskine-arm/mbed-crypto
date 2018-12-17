/*
 *  PSA crypto layer on top of Mbed TLS crypto
 */
/*  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa/crypto.h"

#include "psa_crypto_core.h"
#include "psa_crypto_slot_management.h"
#include "psa_crypto_storage.h"

#include <stdlib.h>
#include <string.h>
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#define ARRAY_LENGTH( array ) ( sizeof( array ) / sizeof( *( array ) ) )

typedef struct
{
    psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];
    unsigned key_slots_initialized : 1;
} psa_global_data_t;

static psa_global_data_t global_data;

/* Access a key slot at the given handle. The handle of a key slot is
 * the index of the slot in the global slot array, plus one so that handles
 * start at 1 and not 0. */
psa_status_t psa_get_key_slot( psa_key_handle_t handle,
                               psa_key_slot_t **p_slot )
{
    psa_key_slot_t *slot = NULL;

    if( ! global_data.key_slots_initialized )
        return( PSA_ERROR_BAD_STATE );

    /* 0 is not a valid handle under any circumstance. This
     * implementation provides slots number 1 to N where N is the
     * number of available slots. */
    if( handle == 0 || handle > ARRAY_LENGTH( global_data.key_slots ) )
        return( PSA_ERROR_INVALID_HANDLE );
    slot = &global_data.key_slots[handle - 1];

    /* If the slot hasn't been allocated, the handle is invalid. */
    if( ! slot->allocated )
        return( PSA_ERROR_INVALID_HANDLE );

    *p_slot = slot;
    return( PSA_SUCCESS );
}

psa_status_t psa_initialize_key_slots( void )
{
    /* Nothing to do: program startup and psa_wipe_all_key_slots() both
     * guarantee that the key slots are initialized to all-zero, which
     * means that all the key slots are in a valid, empty state. */
    global_data.key_slots_initialized = 1;
    return( PSA_SUCCESS );
}

static psa_status_t psa_close_key_slot( psa_key_slot_t *slot )
{
    const psa_drv_external_cryptoprocessor_t *drv =
        psa_get_driver_for_slot( slot );
    if( drv != NULL && drv->close != NULL )
        return( drv->close( slot->data.opaque ) );
    return( psa_wipe_key_slot( slot ) );
}

void psa_wipe_all_key_slots( void )
{
    psa_key_handle_t key;
    for( key = 1; key <= PSA_KEY_SLOT_COUNT; key++ )
    {
        psa_key_slot_t *slot = &global_data.key_slots[key - 1];
        (void) psa_close_key_slot( slot );
    }
    global_data.key_slots_initialized = 0;
}

/** Find a free key slot and mark it as in use.
 *
 * \param[out] handle   On success, a slot number that is not in use. This
 *                      value can be used as a handle to the slot.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
static psa_status_t psa_internal_allocate_key_slot( psa_key_handle_t *handle,
                                                    psa_key_slot_t **p_slot )
{
    *p_slot = NULL;
    for( *handle = PSA_KEY_SLOT_COUNT; *handle != 0; --( *handle ) )
    {
        psa_key_slot_t *slot = &global_data.key_slots[*handle - 1];
        if( ! slot->allocated )
        {
            slot->allocated = 1;
            *p_slot = slot;
            return( PSA_SUCCESS );
        }
    }
    return( PSA_ERROR_INSUFFICIENT_MEMORY );
}

psa_status_t psa_allocate_key( psa_key_type_t type,
                               size_t max_bits,
                               psa_key_handle_t *handle )
{
    psa_key_slot_t *slot;
    /* This implementation doesn't reserve memory for the keys. */
    (void) type;
    (void) max_bits;
    *handle = 0;
    return( psa_internal_allocate_key_slot( handle, &slot ) );
}

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
static psa_status_t psa_load_persistent_key_into_slot( psa_key_slot_t *p_slot )
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;

    status = psa_load_persistent_key( p_slot->persistent_storage_id,
                                      &( p_slot )->type,
                                      &( p_slot )->policy, &key_data,
                                      &key_data_length );
    if( status != PSA_SUCCESS )
        goto exit;
    status = psa_import_key_into_slot( p_slot,
                                       key_data, key_data_length );
exit:
    psa_free_persistent_key_data( key_data, key_data_length );
    return( status );
}
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

/** Declare a slot as persistent and load it from storage.
 *
 * This function may only be called immediately after a successful call
 * to psa_internal_allocate_key_slot() and setting the slot's `lifetime`
 * and `persistent_storage_id` fields.
 *
 * \param slot        A key slot freshly allocated with
 *                    psa_internal_allocate_key_slot(), with `lifetime` set
 *                    to #PSA_KEY_LIFETIME_PERSISTENT and
 *                    `persistent_storage_id` set to the desired persistent
 *                    name for the key.
 * \param create      1 to create a new key.
 *                    0 to open an existing key.
 *
 * \retval #PSA_SUCCESS
 *         If \p create is zero: the slot content was loaded successfully.
 *         If \p create is nonzero: there is no content for this slot
 *         in persistent storage, and it is possible to create such content.
 * \retval #PSA_ERROR_EMPTY_SLOT
 *         \p create is zero and
 *         there is no content for this slot in persistent storage.
 * \retval #PSA_ERROR_OCCUPIED_SLOT
 *         \p create is nonzero and
 *         there is already content for this slot in persistent storage.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         `slot->persistent_storage_id` is not acceptable.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_STORAGE_FAILURE
 */
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
static psa_status_t make_transparent_key_persistent( psa_key_slot_t *slot,
                                                     int create )
{
    psa_status_t status;

    /* Reject id=0 because by general library conventions, 0 is an invalid
     * value wherever possible. */
    if( slot->persistent_storage_id == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );
    /* Reject high values because the file names are reserved for the
     * library's internal use. */
    if( slot->persistent_storage_id >= PSA_MAX_PERSISTENT_KEY_IDENTIFIER )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_load_persistent_key_into_slot( slot );
    if( create && status == PSA_ERROR_EMPTY_SLOT )
        return( PSA_SUCCESS );
    else if( create && status == PSA_SUCCESS )
        return( PSA_ERROR_OCCUPIED_SLOT );
    else
        return( status );
}
#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */

static psa_status_t persistent_key_setup( psa_key_lifetime_t lifetime,
                                          psa_key_id_t id,
                                          psa_key_handle_t *handle,
                                          int create )
{
    psa_status_t status;
    psa_key_slot_t *slot;

    *handle = 0;

    if( lifetime == PSA_KEY_LIFETIME_VOLATILE )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_internal_allocate_key_slot( handle, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    slot->lifetime = lifetime;
    slot->persistent_storage_id = id;

    if( lifetime == PSA_KEY_LIFETIME_PERSISTENT )
    {
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
        status = make_transparent_key_persistent( slot, create );
#else /* MBEDTLS_PSA_CRYPTO_STORAGE_C */
        status = PSA_ERROR_NOT_SUPPORTED;
#endif /* !MBEDTLS_PSA_CRYPTO_STORAGE_C */
    }
    else
    {
        const psa_drv_external_cryptoprocessor_t *drv =
            psa_get_driver_for_slot( slot );
        uint32_t flags = create ? PSA_DRV_OPEN_KEY_CREATE : 0;
        if( drv == NULL )
            status = PSA_ERROR_NOT_SUPPORTED;
        else if( drv->open == NULL )
            status = PSA_ERROR_NOT_SUPPORTED;
        else
            status = drv->open( lifetime, id, flags, &slot->data.opaque );
    }

    if( status != PSA_SUCCESS )
    {
        psa_wipe_key_slot( slot );
        *handle = 0;
    }
    return( status );
}

psa_status_t psa_open_key( psa_key_lifetime_t lifetime,
                           psa_key_id_t id,
                           psa_key_handle_t *handle )
{
    return( persistent_key_setup( lifetime, id, handle, 0 ) );
}

psa_status_t psa_create_key( psa_key_lifetime_t lifetime,
                             psa_key_id_t id,
                             psa_key_type_t type,
                             size_t max_bits,
                             psa_key_handle_t *handle )
{
    /* This implementation doesn't reserve memory for the keys. */
    (void) type;
    (void) max_bits;

    return( persistent_key_setup( lifetime, id, handle, 1 ) );
}

psa_status_t psa_close_key( psa_key_handle_t handle )
{
    psa_key_slot_t *slot;
    psa_status_t status;
    status = psa_get_key_slot( handle, &slot );
    if( status != PSA_SUCCESS )
        return( status );
    return( psa_close_key_slot( slot ) );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */

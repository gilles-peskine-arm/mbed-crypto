#ifndef PSA_INTERNAL_TRUSTED_STORAGE_H
#define PSA_INTERNAL_TRUSTED_STORAGE_H

typedef uint64_t psa_storage_uid_t;

typedef struct psa_storage_info_t {
    size_t size;
} psa_storage_info_t;

psa_status_t psa_its_get(psa_storage_uid_t uid,
                         uint32_t flags,
                         size_t buffer_size,
                         unsigned char *buffer);
psa_status_t psa_its_get_info(psa_storage_uid_t uid,
                              psa_storage_info_t *info);
psa_status_t psa_its_set(psa_storage_uid_t uid,
                         size_t buffer_size,
                         const unsigned char *buffer,
                         uint32_t flags);
psa_status_t psa_its_remove(psa_storage_uid_t uid);
#endif /* PSA_INTERNAL_TRUSTED_STORAGE_H */

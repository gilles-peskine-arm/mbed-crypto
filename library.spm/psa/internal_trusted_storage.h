#ifndef PSA_INTERNAL_TRUSTED_STORAGE_H
#define PSA_INTERNAL_TRUSTED_STORAGE_H
typedef uint32_t psa_its_status_t;
typedef uint64_t psa_its_uid_t;

typedef struct psa_its_info_t {
    size_t size;
} psa_its_info_t;

#define PSA_ITS_SUCCESS 0
#define PSA_ITS_ERROR_FLAGS_NOT_SUPPORTED 1
#define PSA_ITS_ERROR_INCORRECT_SIZE 2
#define PSA_ITS_ERROR_INSUFFICIENT_SPACE 3
#define PSA_ITS_ERROR_INVALID_ARGUMENTS 4
#define PSA_ITS_ERROR_OFFSET_INVALID 5
#define PSA_ITS_ERROR_STORAGE_FAILURE 6
#define PSA_ITS_ERROR_UID_NOT_FOUND 7
#define PSA_ITS_ERROR_WRITE_ONCE 8

psa_its_status_t psa_its_get(psa_its_uid_t uid,
                             uint32_t flags,
                             size_t buffer_size,
                             unsigned char *buffer);
psa_its_status_t psa_its_get_info(psa_its_uid_t uid,
                                  psa_its_info_t *info);
psa_its_status_t psa_its_set(psa_its_uid_t uid,
                             size_t buffer_size,
                             const unsigned char *buffer,
                             uint32_t flags);
psa_its_status_t psa_its_remove(psa_its_uid_t uid);
#endif /* PSA_INTERNAL_TRUSTED_STORAGE_H */

#ifndef VAULTBLOB_H
#define VAULTBLOB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vaultblob_session vaultblob_session;

vaultblob_session* vaultblob_open_vault(
    const char* path,
    const uint8_t* master_key,
    uint64_t max_chunk_size,
    uint64_t max_blob_size,
    int split_files,
    int stripe_chunks,
    int verbose,
    char** error_out
);

void vaultblob_close(vaultblob_session* session);

int vaultblob_put_file(
    vaultblob_session* session,
    const uint8_t* data,
    size_t data_len,
    const char* file_id,
    char** out_file_id,
    char** error_out
);

uint8_t* vaultblob_read_file(
    vaultblob_session* session,
    const char* file_id,
    size_t* out_len,
    char** error_out
);

int vaultblob_file_size(
    vaultblob_session* session,
    const char* file_id,
    uint64_t* out_size,
    char** error_out
);

int vaultblob_read_file_range(
    vaultblob_session* session,
    const char* file_id,
    uint64_t offset,
    uint64_t length,
    uint8_t** out_data,
    size_t* out_len,
    char** error_out
);

int vaultblob_blob_ids(
    vaultblob_session* session,
    char*** out_ids,
    size_t* out_count,
    char** error_out
);

void vaultblob_free_string(char* s);

void vaultblob_free_string_array(char** arr, size_t count);

void vaultblob_free_bytes(uint8_t* ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif

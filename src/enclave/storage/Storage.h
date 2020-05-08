#ifndef _CRUST_STORAGE_H_
#define _CRUST_STORAGE_H_

#include <vector>
#include <set>
#include <tuple>
#include "sgx_trts.h"
#include "Node.h"
#include "MerkleTree.h"
#include "Workload.h"
#include "Parameter.h"
#include "EUtils.h"

using namespace std;


#if defined(__cplusplus)
extern "C"
{
#endif

crust_status_t storage_validate_merkle_tree(MerkleTree *root);

crust_status_t storage_seal_data(const uint8_t *root_hash, uint32_t root_hash_len,
        const uint8_t *p_src, size_t src_len, uint8_t *p_sealed_data, size_t sealed_data_size);

crust_status_t storage_seal_file(MerkleTree *root, const char *path, size_t path_len, char *p_new_path);

crust_status_t storage_unseal_file(char **files, size_t files_num, const char *p_dir, char *p_new_path);

crust_status_t storage_unseal_data(const uint8_t *p_sealed_data, size_t sealed_data_size,
        uint8_t *p_unsealed_data, uint32_t unsealed_data_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_STORAGE_H_ */

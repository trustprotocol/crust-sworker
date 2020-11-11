#include "IpfsOCalls.h"

/**	
 * @description: Test if there is usable IPFS	
 * @return: Test result	
 * */
bool ocall_ipfs_online()
{
    return Ipfs::get_instance()->online();
}

/**	
 * @description: Get block from ipfs	
 * @return: Status	
 * */
crust_status_t ocall_ipfs_block_get(const char *cid, unsigned char **p_data, size_t *len)
{
    *len = Ipfs::get_instance()->block_get(cid, p_data);
    if (*len == 0)
    {
        return CRUST_STORAGE_IPFS_BLOCK_GET_ERROR;
    }
    return CRUST_SUCCESS;
}

/**	
 * @description: Cat file	
 * @return: Status	
 * */
crust_status_t ocall_ipfs_cat(const char *cid, unsigned char **p_data, size_t *len)
{
    *len = Ipfs::get_instance()->cat(cid, p_data);
    if (*len == 0)
    {
        return CRUST_STORAGE_IPFS_CAT_ERROR;
    }
    return CRUST_SUCCESS;
}

/**	
 * @description: Add file to ipfs	
 * @return: Status	
 * */
crust_status_t ocall_ipfs_add(unsigned char *p_data, size_t len)
{
    std::string cid = Ipfs::get_instance()->add(p_data, len);
    if (cid.size() == 0)
    {
        return CRUST_STORAGE_IPFS_ADD_ERROR;
    }
    return CRUST_SUCCESS;
}
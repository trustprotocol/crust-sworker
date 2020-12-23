#include "Srd.h"

long g_srd_task = 0;
sgx_thread_mutex_t g_srd_task_mutex = SGX_THREAD_MUTEX_INITIALIZER;
uint8_t *g_base_rand_buffer = NULL;
sgx_thread_mutex_t g_base_rand_buffer_mutex = SGX_THREAD_MUTEX_INITIALIZER;

// TODO: store in DB with bytes
/**
 * @description: call ocall_save_file to save file
 * @param g_path -> g folder path
 * @param index -> m file's index
 * @param hash -> m file's hash
 * @param data -> m file's data
 * @param data_size -> the length of m file's data
 * @return: Save status
 */
crust_status_t save_file(const char *g_path, size_t index, sgx_sha256_hash_t hash, const unsigned char *data, size_t data_size)
{
    std::string file_path = get_leaf_path(g_path, index, hash);
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_save_file(&crust_status, file_path.c_str(), data, data_size);
    return crust_status;
}

/**
 * @description: call ocall_save_file to save m_hashs.bin file
 * @param g_path -> g folder path
 * @param data -> data
 * @param data_size -> the length of data
 * @return: Save status
 */
crust_status_t save_m_hashs_file(const char *g_path, const unsigned char *data, size_t data_size)
{
    std::string file_path = get_m_hashs_file_path(g_path);
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_save_file(&crust_status, file_path.c_str(), data, data_size);
    return crust_status;
}

/**
 * @description: Do srd
 */
void srd_change()
{
    Workload *wl = Workload::get_instance();
    if (ENC_UPGRADE_STATUS_SUCCESS == wl->get_upgrade_status())
    {
        return;
    }

    sgx_thread_mutex_lock(&g_srd_task_mutex);

    // Get real srd space
    long srd_change_num = 0;
    if (g_srd_task > SRD_MAX_PER_TURN)
    {
        srd_change_num = SRD_MAX_PER_TURN;
        g_srd_task -= SRD_MAX_PER_TURN;
    }
    else
    {
        srd_change_num = g_srd_task;
        g_srd_task = 0;
    }

    // Store remaining task
    std::string srd_task_str = std::to_string(g_srd_task);
    if (CRUST_SUCCESS != persist_set_unsafe(WL_SRD_REMAINING_TASK, reinterpret_cast<const uint8_t *>(srd_task_str.c_str()), srd_task_str.size()))
    {
        log_warn("Store srd remaining task failed!\n");
    }
    sgx_thread_mutex_unlock(&g_srd_task_mutex);

    // Do srd
    if (srd_change_num != 0)
    {
        ocall_srd_change(srd_change_num);
    }

    // Update srd info
    crust_status_t crust_status = CRUST_SUCCESS;
    std::string srd_info_str = wl->get_srd_info().dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Set srd info failed! Error code:%lx\n", crust_status);
    }
}

/**
 * @description: seal one G srd files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void srd_increase(const char *path)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    Workload *wl = Workload::get_instance();
    std::string path_str(path);

    // Generate base random data
    do
    {
        if (g_base_rand_buffer == NULL)
        {
            SafeLock sl(g_base_rand_buffer_mutex);
            sl.lock();
            if (g_base_rand_buffer != NULL)
            {
                break;
            }
            g_base_rand_buffer = (uint8_t *)enc_malloc(SRD_RAND_DATA_LENGTH);
            if (g_base_rand_buffer == NULL)
            {
                log_err("Malloc memory failed!\n");
                return;
            }
            memset(g_base_rand_buffer, 0, SRD_RAND_DATA_LENGTH);
            sgx_read_rand(g_base_rand_buffer, sizeof(g_base_rand_buffer));
        }
    } while (0);

    // Generate current G hash index
    size_t now_index = 0;
    sgx_read_rand((unsigned char *)&now_index, 8);

    // ----- Generate srd file ----- //
    // Create directory
    std::string g_path = get_g_path(path, now_index);
    ocall_create_dir(&crust_status, g_path.c_str());
    if (CRUST_SUCCESS != crust_status)
    {
        return;
    }

    // Generate all M hashs and store file to disk
    uint8_t *hashs = (uint8_t *)enc_malloc(SRD_RAND_DATA_NUM * HASH_LENGTH);
    if (hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return;
    }
    for (size_t i = 0; i < SRD_RAND_DATA_NUM; i++)
    {
        crust_status = seal_data_mrenclave(g_base_rand_buffer, SRD_RAND_DATA_LENGTH, &p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            return;
        }

        sgx_sha256_hash_t out_hash256;
        sgx_sha256_msg((uint8_t *)p_sealed_data, SRD_RAND_DATA_LENGTH, &out_hash256);

        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            hashs[i * HASH_LENGTH + j] = out_hash256[j];
        }

        save_file(g_path.c_str(), i, out_hash256, (unsigned char *)p_sealed_data, SRD_RAND_DATA_LENGTH);

        free(p_sealed_data);
        p_sealed_data = NULL;
    }

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, SRD_RAND_DATA_NUM * HASH_LENGTH, &g_out_hash256);

    save_m_hashs_file(g_path.c_str(), hashs, SRD_RAND_DATA_NUM * HASH_LENGTH);
    free(hashs);

    // Change G path name
    std::string new_g_path = get_g_path_with_hash(path, g_out_hash256);
    ocall_rename_dir(&crust_status, g_path.c_str(), new_g_path.c_str());

    // Get g hash
    uint8_t *p_hash_u = (uint8_t *)enc_malloc(HASH_LENGTH);
    if (p_hash_u == NULL)
    {
        log_info("Seal random data failed! Malloc memory failed!\n");
        return;
    }
    memset(p_hash_u, 0, HASH_LENGTH);
    memcpy(p_hash_u, g_out_hash256, HASH_LENGTH);

    // ----- Update srd_hashs ----- //
    std::string hex_g_hash = hexstring_safe(p_hash_u, HASH_LENGTH);
    if (hex_g_hash.compare("") == 0)
    {
        log_err("Hexstring failed!\n");
        return;
    }
    // Add new g_hash to srd_hashs
    // Because add this p_hash_u to the srd_hashs, so we cannot free p_hash_u
    sgx_thread_mutex_lock(&wl->srd_mutex);
    wl->srd_hashs.push_back(p_hash_u);
    log_info("Seal random data -> %s, %luG success\n", hex_g_hash.c_str(), wl->srd_hashs.size());
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Update srd info ----- //
    wl->set_srd_info(1);
}

/**
 * @description: Decrease srd files under directory
 * @param change -> Total to be deleted space volumn
 * @param clear_metadata -> Clear metadata
 * @return: Decreased size
 */
size_t srd_decrease(size_t change, bool clear_metadata)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    uint32_t real_change = 0;

    // Choose to be deleted g_hash index
    SafeLock sl(wl->srd_mutex);
    sl.lock();

    if (clear_metadata)
    {
        wl->deal_deleted_srd(false);
    }
    
    // Get real change
    change = std::min(change, wl->srd_hashs.size());
    if (change == 0)
    {
        return 0;
    }

    // Get change set
    std::vector<uint8_t *> srd_del_hashs;
    for (size_t i = wl->srd_hashs.size() - 1; i >= 0; i--)
    {
        wl->add_srd_to_deleted_buffer(i);
        uint8_t *tmp = (uint8_t *)enc_malloc(HASH_LENGTH);
        if (tmp == NULL)
        {
            log_info("Malloc memory failed!\n");
            for (size_t j = 0; j < srd_del_hashs.size(); j++)
            {
                free(srd_del_hashs[j]);
            }
            srd_del_hashs.clear();
            return 0;
        }
        memset(tmp, 0, HASH_LENGTH);
        memcpy(tmp, wl->srd_hashs[i], HASH_LENGTH);
        srd_del_hashs.push_back(tmp);
    }

    // Delete metadata
    if (clear_metadata)
    {
        wl->deal_deleted_srd(false);
    }
    sl.unlock();

    // Delete srd files
    for (auto del_hash : srd_del_hashs)
    {
        // --- Delete srd file --- //
        // TODO : hard code
        std::string del_path = "/opt/crust/crust-sworker/0.7.0/sworker_base_path/data/srd" + hexstring_safe(del_hash, HASH_LENGTH);
        ocall_delete_folder_or_file(&crust_status, del_path.c_str());
        if (CRUST_SUCCESS != crust_status)
        {
            log_warn("Delete path:%s failed! Error code:%lx\n", del_path.c_str(), crust_status);
        }
    }

    return real_change;
}

/**
 * @description: Remove space outside main loop
 * @param change -> remove size
 */
void srd_remove_space(size_t change)
{
    log_debug("Disk path:%s will free %ldG srd space for meaningful data. This is normal.\n", srd_decrease(change, false));
}

/**
 * @description: Get srd change
 * @return: Srd change 
 */
long get_srd_task()
{
    sgx_thread_mutex_lock(&g_srd_task_mutex);
    long srd_change = g_srd_task;
    sgx_thread_mutex_unlock(&g_srd_task_mutex);

    return srd_change;
}

/**
 * @description: Set srd change
 * @param change -> Srd change
 */
crust_status_t change_srd_task(long change, long *real_change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    // Check if srd number exceeds upper limit
    if (change > 0)
    {
        Workload *wl = Workload::get_instance();
        sgx_thread_mutex_lock(&wl->srd_mutex);
        size_t srd_num = wl->srd_hashs.size();
        sgx_thread_mutex_unlock(&wl->srd_mutex);
        
        if (srd_num >= SRD_NUMBER_UPPER_LIMIT)
        {
            log_warn("No srd will be added!Srd size has reached the upper limit:%ldG!\n", SRD_NUMBER_UPPER_LIMIT);
            change = 0;
            crust_status = CRUST_SRD_NUMBER_EXCEED;
        }
        else if (srd_num + change > SRD_NUMBER_UPPER_LIMIT)
        {
            log_warn("To be added srd number:%ldG(srd upper limit:%ldG)\n", change, SRD_NUMBER_UPPER_LIMIT);
            change = SRD_NUMBER_UPPER_LIMIT - srd_num;
            crust_status = CRUST_SRD_NUMBER_EXCEED;
        }
    }

    sgx_thread_mutex_lock(&g_srd_task_mutex);
    g_srd_task += change;
    // Store remaining task
    std::string srd_task_str = std::to_string(g_srd_task);
    if (CRUST_SUCCESS != persist_set_unsafe(WL_SRD_REMAINING_TASK, reinterpret_cast<const uint8_t *>(srd_task_str.c_str()), srd_task_str.size()))
    {
        log_warn("Store srd remaining task failed!\n");
    }
    sgx_thread_mutex_unlock(&g_srd_task_mutex);

    *real_change = change;

    return crust_status;
}

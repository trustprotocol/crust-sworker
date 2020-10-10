#include "Data.h"

// Store sworker identity
std::string g_sworker_identity = "";
// Store order report
std::string g_order_report = "";
// Store enclave identity information
std::string g_enclave_id_info = "";
// Store enclave workload information
std::string g_enclave_workload = "";
// Store signed work report
std::string g_enclave_workreport = "";
// New karst url
std::string g_new_karst_url = "";

std::string get_g_sworker_identity()
{
    return g_sworker_identity;
}

void set_g_sworker_identity(std::string identity)
{
    g_sworker_identity = identity;
}

std::string get_g_order_report()
{
    return g_order_report;
}

void set_g_order_report(std::string order_report)
{
    g_order_report = order_report;
}

std::string get_g_enclave_id_info()
{
    return g_enclave_id_info;
}

void set_g_enclave_id_info(std::string id_info)
{
    g_enclave_id_info = id_info;
}

std::string get_g_enclave_workload()
{
    return g_enclave_workload;
}

void set_g_enclave_workload(std::string workload)
{
    g_enclave_workload = workload;
}

std::string get_g_enclave_workreport()
{
    return g_enclave_workreport;
}

void set_g_enclave_workreport(std::string workreport)
{
    g_enclave_workreport = workreport;
}

std::string get_g_new_karst_url()
{
    return g_new_karst_url;
}

void set_g_new_karst_url(std::string karst_url)
{
    g_new_karst_url = karst_url;
}

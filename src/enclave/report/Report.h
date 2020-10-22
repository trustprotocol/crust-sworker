#ifndef _CRUST_REPORT_H_
#define _CRUST_REPORT_H_

#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>

#include "Workload.h"
#include "Identity.h"
#include "EUtils.h"
#include "Schedule.h"

crust_status_t get_signed_work_report(const char *block_hash, size_t block_height, bool locked = true);
std::string get_generated_work_report();

#endif /* !_CRUST_REPORT_H_ */

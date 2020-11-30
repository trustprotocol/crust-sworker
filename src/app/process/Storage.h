#ifndef _APP_STORAGE_H_
#define _APP_STORAGE_H_

#include <string>
#include <future>
#include "Log.h"
#include "ECalls.h"


#if defined(__cplusplus)
extern "C"
{
#endif

void storage_add_delete(std::string cid);

void storage_add_seal(std::string cid);

#if defined(__cplusplus)
}
#endif

#endif /* ! _APP_STORAGE_H_ */

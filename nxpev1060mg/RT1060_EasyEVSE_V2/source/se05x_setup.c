/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#include <se05x_setup.h>
#include "PlugAndTrust_Pkg_Ver.h"
#include "string.h" /* memset */
#include "tx_api.h"


AT_NONCACHEABLE_SECTION_ALIGN(ex_sss_boot_ctx_t gex_sss_boot_ctx,64);

#ifdef USE_THREADX_RTOS
AT_NONCACHEABLE_SECTION_ALIGN( uint8_t se05x_byte_pool[SE05X_BYTE_POOL_SIZE],64);
#endif


int SE05x_Init()
{
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    const char *portName = NULL;

#ifdef USE_THREADX_RTOS
    // Initialize the SE05x T1oI2C internal ThreadX memory pool
    uint32_t retval = phNxpEse_ThreadX_MemallocInit((void *)se05x_byte_pool, sizeof(se05x_byte_pool));
	if(TX_SUCCESS != retval)
	{
		LOG_I("phNxpEse_ThreadX_MemallocInit failed...\r\n");
		while(1);
	}
#endif

    LOG_I(PLUGANDTRUST_PROD_NAME_VER_FULL);

    memset(PCONTEXT, 0, sizeof(*PCONTEXT));

    LOG_E("ex_sss_boot_open()...");
    status = ex_sss_boot_open(&gex_sss_boot_ctx, portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_session_open Failed");
        return status;
    }

    if (kType_SSS_SubSystem_NONE == ((PCONTEXT)->session.subsystem)) {
        /* Nothing to do. Device is not opened
         * This is needed for the case when we open a generic communication
         * channel, without being specific to SE05X
         */
    }
    else {
        status = ex_sss_key_store_and_object_init((PCONTEXT));
        if (kStatus_SSS_Success != status) {
            LOG_E("ex_sss_key_store_and_object_init Failed");
            return status;
        }
    }

    return status;
}

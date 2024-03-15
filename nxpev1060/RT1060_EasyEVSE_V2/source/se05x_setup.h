/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SE05X_SETUP_H_
#define SE05X_SETUP_H_

#include "ex_sss_boot.h"
#include "fsl_sss_se05x_apis.h"
#include "nxLog_App.h"
#include "se05x_APDU.h"
#include "se05x_const.h"
#include "se05x_ecc_curves.h"
#include "se05x_ecc_curves_values.h"
#include "se05x_tlv.h"
#include "se05x_sss_boot_pcontext.h"
#ifdef USE_THREADX_RTOS
	#define SE05X_BYTE_POOL_SIZE  640
	#include "phNxpEse_Api.h"
	extern uint8_t se05x_byte_pool[SE05X_BYTE_POOL_SIZE];
#endif

	int SE05x_Init();

#endif /* SE05X_SETUP_H_ */

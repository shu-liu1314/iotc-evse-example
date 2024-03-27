/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SE05X_SSS_BOOT_PCONTEXT_H_
#define SE05X_SSS_BOOT_PCONTEXT_H_

	extern ex_sss_boot_ctx_t gex_sss_boot_ctx;

	#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
	#define PCONTEXT EX_SSS_BOOT_PCONTEXT

#endif /* SE05X_SSS_BOOT_PCONTEXT_H_ */

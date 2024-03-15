/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SE05X_SAMPLE_H_
#define SE05X_SAMPLE_H_

#include <se05x_setup.h>
#include "se05x_nx_debug_printf.h"
#include "se05x_nx_ecdsa.h"
#include "se05x_GetCertificate.h"
#include "se05x_nx_ecdsa_sign.h"
#include "se05x_nx_get_random.h"
#include "se05x_GetRandom.h"

#define SE05x_STACKSIZE 	1024 * 9

#define SE05X_CLIENT_CERTIFICATE_SIZE			512
#define SSS_KEYPAIR_INDEX_CLIENT_PRIVATE 		0x223344
#define SSS_CERTIFICATE_INDEX_CLIENT 			0x223345

#endif /* SE05X_SAMPLE_H_ */

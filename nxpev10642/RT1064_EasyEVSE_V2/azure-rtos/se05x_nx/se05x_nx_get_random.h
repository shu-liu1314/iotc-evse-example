/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SE05X_NX_GET_RANDOM_H_
#define SE05X_NX_GET_RANDOM_H_
#include "tx_api.h"

#define SE05X_NX_RANDOM  1

typedef UINT (*se05x_nx_get_random_callback_t)(	UCHAR *random_data, UINT random_dataLen );


VOID se05x_nx_get_random_init(se05x_nx_get_random_callback_t cb);

UINT se05x_rand();
VOID se05x_randomBytes(UCHAR *random_data, UINT random_dataLen );

#endif /* SE05X_NX_GET_RANDOM_H_ */

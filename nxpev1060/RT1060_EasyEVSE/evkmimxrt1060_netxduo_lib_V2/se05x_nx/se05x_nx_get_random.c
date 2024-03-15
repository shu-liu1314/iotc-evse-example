/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#include "tx_api.h"
#include "nx_crypto_const.h"
#include "se05x_nx_get_random.h"
#include "se05x_nx_debug_printf.h"
#include "stdlib.h"


#define SSS_SUCCESS 0x5a5a5a5au

static se05x_nx_get_random_callback_t _se05x_nx_get_random_callback_t = TX_NULL;


VOID se05x_nx_get_random_init(se05x_nx_get_random_callback_t cb)
{

	_se05x_nx_get_random_callback_t = cb;
}


UINT se05x_rand()
{

	UCHAR random_bytes[4];

	UINT random_int = 0;

	UINT status =  _se05x_nx_get_random_callback_t(random_bytes, 4);

	random_int = ((UINT)random_bytes[3] << 24) | ((UINT)random_bytes[2] << 16) | ((UINT)random_bytes[1] << 8) | random_bytes[0];
	return random_int;
}

VOID se05x_randomBytes(UCHAR *random_data, UINT random_dataLen )
{
	UINT status =  _se05x_nx_get_random_callback_t(random_data, random_dataLen);
}

/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#include "tx_api.h"
#include "nx_crypto_const.h"
#include "se05x_nx_ecdsa.h"


#define SSS_SUCCESS 0x5a5a5a5au

static se05x_nx_ecdsa_sign_callback_t _se05x_nx_ecdsa_sign_callback_t = TX_NULL;
static UINT _privateKeyId = 0;

VOID se05x_nx_ecdsa_sign_init(UINT privKeyId, se05x_nx_ecdsa_sign_callback_t cb)
{
	_privateKeyId = privKeyId;
	_se05x_nx_ecdsa_sign_callback_t = cb;
}


UINT _nx_crypto_ecdsa_sign_se05x_wrapper(UCHAR *hash, UINT hash_length,
                                UCHAR *signature, ULONG signature_buffer_size,
								ULONG *actual_signature_length)
{

	UINT sigLen = signature_buffer_size;

	UINT status =  _se05x_nx_ecdsa_sign_callback_t(_privateKeyId, hash, hash_length, signature, &sigLen);

	if( status == SSS_SUCCESS)
	{
		*actual_signature_length = sigLen;
		return NX_CRYPTO_SUCCESS;
	}
	else
	{
		*actual_signature_length = 0;
		return NX_CRYPTO_NOT_SUCCESSFUL;
	}
}

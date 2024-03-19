/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SE05X_NX_ECDSA_H_
#define SE05X_NX_ECDSA_H_

#include "tx_api.h"

#define SE05X_NX_CRYPTO_AUTHENTICATE	1

typedef UINT (*se05x_nx_ecdsa_sign_callback_t)(	UINT privateKeyId,
												UCHAR *inputDigest, UINT inputDigestLength,
												UCHAR *signature, UINT *signatureLen);


VOID se05x_nx_ecdsa_sign_init(UINT privKeyId, se05x_nx_ecdsa_sign_callback_t cb);


UINT _nx_crypto_ecdsa_sign_se05x_wrapper(UCHAR *hash, UINT hash_length,
                                UCHAR *signature, ULONG signature_buffer_size,
								ULONG *actual_signature_length);

#endif /* SE05X_NX_ECDSA_H_ */

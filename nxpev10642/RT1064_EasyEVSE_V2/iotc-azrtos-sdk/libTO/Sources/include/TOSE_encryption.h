/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019 Trusted Objects. All rights reserved.
 */

/**
 * @file TOSE_encryption.h
 * @brief
 */

#ifndef _TOSE_ENCRYPTION_H_
#define _TOSE_ENCRYPTION_H_

#ifndef TOSE_ENCRYPTION_API
#ifdef __linux__
#define TOSE_ENCRYPTION_API
#elif _WIN32
#define TOSE_ENCRYPTION_API __declspec(dllexport)
#else
#define TOSE_ENCRYPTION_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup encryption
 * @{ */

/**
 * @brief Encrypts data using AES128 algorithm in CBC mode of
 * operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data encryption, starting
 * from 0
 * @param[in] data Data to encrypt
 * @param[in] data_length Length of the data to encrypt
 * @param[out] initial_vector Initial vector
 * @param[out] cryptogram Cryptogram, sent back by the Secure Element
 *
 * As padding is not handled by the Secure Element, you must ensure that data
 * length is a multiple of 16 and is not greater than maximum length value (512
 * bytes).
 * Initial vector is generated by the Secure Element.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_INVALID_LEN: Wrong length
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128cbc_encrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram);

/**
 * @brief Similar to encrypt() except that Initial Vector is
 * given by user
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data encryption, starting
 * from 0
 * @param[in] initial_vector Random data (16 bytes)
 * @param[in] data Data to encrypt
 * @param[in] data_length
 * @param[out] cryptogram Returned encrypted data
 *
 * It can be used to encrypt more than data size limit (512 bytes) by manually
 * chaining blocs of 512 bytes (see Secure Element Datasheet - "Encrypt or
 * decrypt more than 512 bytes" chapter for more details).
 * @warning Using iv_encrypt() with a predictable Initial Vector can have
 *    security impact. Please let Secure Element generate Initial Vector by
 *    using encrypt() command when possible.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128cbc_iv_encrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram);

/**
 * @brief Decrypts data using AES128 algorithm in CBC mode of operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data decryption, starting
 * from 0
 * @param[in] initial_vector Initial vector
 * @param[in] cryptogram Data to decrypt
 * @param[in] cryptogram_length Cryptogram length, less or equal to 512 bytes
 * @param[out] data returned decrypted data
 *
 * Requires the initial vector provided by the encryption function.
 *
 * Padding is not handled by Secure Element firmware. It gives the possibility
 * to avoid the case of a full padding block sometimes required by padding
 * functions.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128cbc_decrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data);

/**
 * @brief Encrypts data using AES128 algorithm in GCM mode of operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data encryption, starting
 * from 0
 * @param[in] data Data to encrypt
 * @param[in] data_length Length of the data to encrypt
 * @param[in] aad Additional authentication data
 * @param[in] aad_length Length of the additional authentication data
 * @param[out] initial_vector Initial vector
 * @param[out] cryptogram Cryptogram
 * @param[out] tag Authentication tag
 *
 * Additional authentication data length and data length can not exceed
 * driver IO buffer size (if applicable).
 * Initial vector is generated by the Secure Element.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_INVALID_LEN: Wrong length
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128gcm_encrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		const uint8_t* aad, const uint16_t aad_length,
		uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint8_t tag[TO_AESGCM_TAG_SIZE]);

/**
 * @brief Decrypts data using AES128 algorithm in GCM mode of operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data decryption, starting
 * from 0
 * @param[in] initial_vector Initial vector
 * @param[in] aad Additional authentication data
 * @param[in] aad_length Length of the additional authentication data
 * @param[in] cryptogram Data to decrypt
 * @param[in] cryptogram_length Cryptogram length, less or equal to 512 bytes
 * @param[in] tag Authentication tag
 * @param[out] data returned decrypted data
 *
 * Requires the initial vector provided by the encryption function.
 * Additional authentication data length and cryptogram length can not exceed
 * driver IO buffer size (if applicable).
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128gcm_decrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		const uint8_t* aad, const uint16_t aad_length,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESGCM_TAG_SIZE], uint8_t* data);

/**
 * @brief Encrypts data using AES128 algorithm in CCM mode of operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data encryption, starting
 * from 0
 * @param[in] data Data to encrypt
 * @param[in] data_length Length of the data to encrypt
 * @param[in] aad Additional authentication data
 * @param[in] aad_length Length of the additional authentication data
 * @param[in] nonce Nonce
 * @param[out] cryptogram Cryptogram
 * @param[out] tag Authentication tag
 *
 * Additional authentication data length and data length can not exceed
 * driver IO buffer size (if applicable).
 * Nonce is generated by the Secure Element.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_INVALID_LEN: Wrong length
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128ccm_encrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		const uint8_t* aad, const uint16_t aad_length,
		uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		uint8_t* cryptogram, uint8_t tag[TO_AESCCM_TAG_SIZE]);

/**
 * @brief Decrypts data using AES128 algorithm in CCM mode of operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data decryption, starting
 * from 0
 * @param[in] nonce Nonce
 * @param[in] aad Additional authentication data
 * @param[in] aad_length Length of the additional authentication data
 * @param[in] cryptogram Data to decrypt
 * @param[in] cryptogram_length Cryptogram length, less or equal to 512 bytes
 * @param[in] tag Authentication tag
 * @param[out] data returned decrypted data
 *
 * Requires the nonce provided by the encryption function.
 * Additional authentication data length and cryptogram length can not exceed
 * driver IO buffer size (if applicable).
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128ccm_decrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		const uint8_t* aad, const uint16_t aad_length,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESCCM_TAG_SIZE], uint8_t* data);

/**
 * @brief Encrypts data using AES128 algorithm in ECB mode of
 * operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data encryption, starting
 * from 0
 * @param[in] data Data to encrypt
 * @param[in] data_length Length of the data to encrypt
 * @param[out] cryptogram Cryptogram
 *
 * As padding is not handled by the Secure Element, you must ensure that data
 * length is a multiple of 16 and is not greater than maximum length value (512
 * bytes).
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_INVALID_LEN: Wrong length
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128ecb_encrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram);

/**
 * @brief Decrypts data using AES128 algorithm in ECB mode of operation.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for data decryption, starting
 * from 0
 * @param[in] cryptogram Data to decrypt
 * @param[in] cryptogram_length Cryptogram length, less or equal to 512 bytes
 * @param[out] data returned decrypted data
 *
 * Padding is not handled by Secure Element firmware. It gives the possibility
 * to avoid the case of a full padding block sometime required by padding
 * functions.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_ENCRYPTION_API TO_ret_t TOSE_aes128ecb_decrypt(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_ENCRYPTION_H_ */


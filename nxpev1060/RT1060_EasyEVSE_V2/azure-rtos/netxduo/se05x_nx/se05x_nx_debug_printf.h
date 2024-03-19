/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SE05X_NX_DEBUG_PRINTF_H_
#define SE05X_NX_DEBUG_PRINTF_H_

#define SE05X_NX_ENABLE_DEBUG_PRINT 1


typedef int (*printf_callback_t)(const char *fmt_s, ...);

int se05x_nx_debug_printf_init(printf_callback_t cb);
int se05x_nx_debug_printf(const char *format, ...);
int se05x_nx_debug_print_array(UCHAR *array, UINT arrayLength);


#if SE05X_NX_ENABLE_DEBUG_PRINT
	#define SE05X_NX_DEBUG_PRINTF(format, ...) \
			se05x_nx_debug_printf(format, ##__VA_ARGS__)
#	define SE05X_NX_DEBUG_PRINT_ARRAY(ARRAY, LEN) \
		se05x_nx_debug_print_array(ARRAY, LEN)
#else
#	define SE05X_NX_DEBUG_PRINTF(...)
#	define SE05X_NX_DEBUG_PRINT_ARRAY(ARRAY, LEN)
#endif


#endif /* SE05X_NX_DEBUG_PRINTF_H_ */

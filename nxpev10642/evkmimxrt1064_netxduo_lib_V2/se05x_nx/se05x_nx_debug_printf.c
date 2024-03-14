/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdarg.h>
#include <stdio.h>
#include "tx_api.h"
#include "se05x_nx_debug_printf.h"


static printf_callback_t _printf_callback = TX_NULL;


int se05x_nx_debug_printf_init(printf_callback_t cb)
{
	_printf_callback = cb;
}


int se05x_nx_debug_printf(const char *format, ...)
{
	if(_printf_callback != NULL)
	{
		_printf_callback("\r\n");
		_printf_callback("[NETDUO LIB INFO] ");

		char buffer[256];
		size_t size_buff = sizeof(buffer) / sizeof(buffer[0]) - 1;
		va_list vArgs;
		va_start(vArgs, format);
		vsnprintf(buffer, size_buff, format, vArgs);
		va_end(vArgs);
		_printf_callback("%s", buffer);
		_printf_callback("\r\n");
	}
}


int se05x_nx_debug_print_array(UCHAR *array, UINT arrayLength)
{
	if(_printf_callback != NULL)
	{
		for(int i = 0; i < arrayLength; i++ )
		{
			if(i > 0 && i % 16 == 0)
				_printf_callback("\r\n");

			_printf_callback("%02X ", array[i]);
		}
		_printf_callback("\r\n");
	}
}


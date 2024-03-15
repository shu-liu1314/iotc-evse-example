/*
 * Copyright 2016-2018 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 */

#include <sm_timer.h>
#include <stdint.h>

#include "board.h"
#include "tx_api.h"


#ifdef __ICCARM__
#pragma optimize=none
#endif
#if defined(__GNUC__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif


#if defined(USE_THREADX_RTOS)

#define WEAK __attribute__ ((weak))



void sm_sleep(uint32_t msec)
{
	if( TX_TIMER_TICKS_PER_SECOND == 100)
	{
		if(msec <= 10)
		{
			tx_thread_sleep(1); // 1 tick == 10ms
		}
		else
		{
			tx_thread_sleep((ULONG)(msec / 10) + 1);
		}
	}
	else if( TX_TIMER_TICKS_PER_SECOND == 1000)
	{
		tx_thread_sleep(msec); // 1 tick == 1ms
	}
}

#if defined(__GNUC__)
#pragma GCC pop_options
#endif

#endif /* USE_THREADX_RTOS */

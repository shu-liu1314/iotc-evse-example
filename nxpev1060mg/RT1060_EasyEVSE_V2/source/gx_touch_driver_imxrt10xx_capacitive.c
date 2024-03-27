/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** GUIX Component                                                        */
/**                                                                       */
/**   Touch Component    (Touch)                                          */
/**                                                                       */
/**************************************************************************/

#include "tx_api.h"
#include "gx_api.h"
#include "fsl_debug_console.h" /* needed for PRINTF */
#include "display_support.h"
#include "fsl_lpi2c.h"
#include "board.h"
/* Notes

This file contains the hardware-specific functions of the resistive touch
driver. The generic portions of the touch driver are provided by the file
gx_generic_resistive_touch

*/

#include "fsl_lpi2c.h"
#if defined(DEMO_PANEL) && (DEMO_PANEL == DEMO_PANEL_RK043FN66HS)
#include "fsl_gt911.h"
#else
#include "fsl_ft5406_rt.h"
#endif

#define BOARD_TOUCH_I2C LPI2C1

/* Select USB1 PLL (480 MHz) as master lpi2c clock source */
#define LPI2C_CLOCK_SOURCE_SELECT (0U)

/* Clock divider for master lpi2c clock source */
#define LPI2C_CLOCK_SOURCE_DIVIDER (0U)

#define BOARD_TOUCH_I2C_CLOCK_FREQ ((CLOCK_GetFreq(kCLOCK_Usb1PllClk) / 8) / (LPI2C_CLOCK_SOURCE_DIVIDER + 1U))
#define BOARD_TOUCH_I2C_BAUDRATE   400000U

/* Define the touch thread control block and stack.  */
TX_THREAD touch_thread;
UCHAR touch_thread_stack[4096];
VOID touch_thread_entry(ULONG thread_input);

#define TOUCH_STATE_TOUCHED  1
#define TOUCH_STATE_RELEASED 2
#define MIN_DRAG_DELTA       10

static int last_pos_x;
static int last_pos_y;
static int curpos_x;
static int curpos_y;

#if defined(DEMO_PANEL) && (DEMO_PANEL == DEMO_PANEL_RK043FN66HS)

	static void gx_delay(uint32_t ms);
	static void BOARD_PullTouchResetPin(bool pullUp);
	static void BOARD_ConfigTouchIntPin(gt911_int_pin_mode_t mode);

	static gt911_handle_t s_touchHandle;

	static const gt911_config_t s_touchConfig = {
		.I2C_SendFunc     = BOARD_Touch_I2C_Send,
		.I2C_ReceiveFunc  = BOARD_Touch_I2C_Receive,
		.pullResetPinFunc = BOARD_PullTouchResetPin,
		.intPinFunc       = BOARD_ConfigTouchIntPin,
		.timeDelayMsFunc  = gx_delay,
		.touchPointNum    = 1,
		.i2cAddrMode      = kGT911_I2cAddrAny,
		.intTrigMode      = kGT911_IntRisingEdge,
	};
	static int s_touchResolutionX;
	static int s_touchResolutionY;
#endif

static int touch_state;

extern TX_MUTEX mutex_I2C;

/**************************************************************************/
/* called by application to fire off the touch screen driver thread       */
VOID start_touch_thread(void)
{
    /* Create the touch driver thread.  */
    tx_thread_create(&touch_thread, "GUIX Touch Thread", touch_thread_entry, 0, touch_thread_stack,
                     sizeof(touch_thread_stack), GX_SYSTEM_THREAD_PRIORITY - 1, GX_SYSTEM_THREAD_PRIORITY - 1,
                     TX_NO_TIME_SLICE, TX_AUTO_START);
}

/*******************************************************************************
 * Implementation of communication with the touch controller
 ******************************************************************************/

static void gx_touch_init(void)
{
    lpi2c_master_config_t masterConfig = {0};
    LPI2C_MasterGetDefaultConfig(&masterConfig);

    /* Change the default baudrate configuration */
    masterConfig.baudRate_Hz = BOARD_TOUCH_I2C_BAUDRATE;

    /* Initialize the LPI2C master peripheral */
    LPI2C_MasterInit(BOARD_TOUCH_I2C, &masterConfig, BOARD_TOUCH_I2C_CLOCK_FREQ);

    /*Clock setting for LPI2C*/
    // CLOCK_SetMux(kCLOCK_Lpi2cMux, LPI2C_CLOCK_SOURCE_SELECT);
    // CLOCK_SetDiv(kCLOCK_Lpi2cDiv, LPI2C_CLOCK_SOURCE_DIVIDER);
}

void gx_touch_deinit(void)
{
    LPI2C_MasterDeinit(BOARD_TOUCH_I2C);
}

/**************************************************************************/
VOID gx_send_pen_down_event(VOID)
{
    GX_EVENT event;
    event.gx_event_type                                  = GX_EVENT_PEN_DOWN;
    event.gx_event_payload.gx_event_pointdata.gx_point_x = curpos_x;
    event.gx_event_payload.gx_event_pointdata.gx_point_y = curpos_y;
    event.gx_event_sender                                = 0;
    event.gx_event_target                                = 0;
    event.gx_event_display_handle                        = 0;
    gx_system_event_send(&event);
}

/**************************************************************************/
VOID gx_send_pen_drag_event(VOID)
{
    GX_EVENT event;
    int x_delta = abs(curpos_x - last_pos_x);
    int y_delta = abs(curpos_y - last_pos_y);

    if (x_delta > MIN_DRAG_DELTA || y_delta > MIN_DRAG_DELTA)
    {
        event.gx_event_type                                  = GX_EVENT_PEN_DRAG;
        event.gx_event_payload.gx_event_pointdata.gx_point_x = curpos_x;
        event.gx_event_payload.gx_event_pointdata.gx_point_y = curpos_y;
        event.gx_event_sender                                = 0;
        event.gx_event_target                                = 0;
        event.gx_event_display_handle                        = 0;
        last_pos_x                                           = curpos_x;
        last_pos_y                                           = curpos_y;

        gx_system_event_fold(&event);
    }
}

/**************************************************************************/
VOID gx_send_pen_up_event(VOID)
{
    GX_EVENT event;
    event.gx_event_type                                  = GX_EVENT_PEN_UP;
    event.gx_event_payload.gx_event_pointdata.gx_point_x = curpos_x;
    event.gx_event_payload.gx_event_pointdata.gx_point_y = curpos_y;
    event.gx_event_sender                                = 0;
    event.gx_event_target                                = 0;
    event.gx_event_display_handle                        = 0;
    last_pos_x                                           = curpos_x;
    last_pos_y                                           = curpos_y;
    gx_system_event_send(&event);
}

/**************************************************************************/
VOID touch_thread_entry(ULONG thread_input)
{

#if defined(DEMO_PANEL) && (DEMO_PANEL == DEMO_PANEL_RK043FN66HS)
	static int cur_touch_state;
#else
    ft5406_rt_handle_t touch_handle;
    touch_event_t driver_state;
#endif
    status_t status, status2;
    static int touch_x = 0;
    static int touch_y = 0;;

    /* fow now run in polling mode */
    /*
    tx_event_flags_create(&touch_events, "touch_events");
    touch_interrupt_configure();
    */

    gx_touch_init();

#if defined(DEMO_PANEL) && (DEMO_PANEL == DEMO_PANEL_RK043FN66HS)
    status = GT911_Init(&s_touchHandle, &s_touchConfig);
    if (kStatus_Success != status)
    {
    	PRINTF("Touch IC initialization failed\r\n");
    	assert(false);
    }

    GT911_GetResolution(&s_touchHandle, &s_touchResolutionX, &s_touchResolutionY);
#else
    /* Initialize the touch handle. */
    FT5406_RT_Init(&touch_handle, BOARD_TOUCH_I2C);
#endif
    touch_state = TOUCH_STATE_RELEASED;

    tx_thread_sleep(30);

    while (1)
    {
        // tx_event_flags_get(&touch_events, 1, TX_AND_CLEAR, &actual_flags, TX_WAIT_FOREVER);
        tx_thread_sleep(20);
        /* Get the I2C mutex with suspension.  */
        status = tx_mutex_get(&mutex_I2C, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != TX_SUCCESS)
        {
        	PRINTF("Could not get Mutex during touch thread /r/n");
        	break;
        }

#if defined(DEMO_PANEL) && (DEMO_PANEL == DEMO_PANEL_RK043FN66HS)
        status2 = GT911_GetSingleTouch(&s_touchHandle, &touch_x, &touch_y);
#else
        status = FT5406_RT_GetSingleTouch(&touch_handle, &driver_state, &curpos_y, &curpos_x);
#endif

        /* Release the I2C mutex.  */
        status = tx_mutex_put(&mutex_I2C);

        /* Check status.  */
        if (status != TX_SUCCESS)
        {
        	PRINTF("Could not release Mutex during touch thread /r/n");
        	break;
        }


#if defined(DEMO_PANEL) && (DEMO_PANEL == DEMO_PANEL_RK043FN66HS)
        if (status2 == kStatus_Success)
        {
        	cur_touch_state = TOUCH_STATE_TOUCHED;
        }
        else
        {
        	cur_touch_state = TOUCH_STATE_RELEASED;
        }

        curpos_x = touch_x * DEMO_PANEL_WIDTH / s_touchResolutionX;
        curpos_y = touch_y * DEMO_PANEL_HEIGHT / s_touchResolutionY;

        if (cur_touch_state == TOUCH_STATE_TOUCHED)
        {
        	if (touch_state == TOUCH_STATE_RELEASED)
        	{
        		touch_state = TOUCH_STATE_TOUCHED;
        		gx_send_pen_down_event();
        	}
        	else
        	{
        		// test and send pen drag
				gx_send_pen_drag_event();
        	}
        }
        else
        {
        	// no touch, check so see if last was touched
        	if (touch_state == TOUCH_STATE_TOUCHED)
        	{
        		touch_state = TOUCH_STATE_RELEASED;
        		gx_send_pen_up_event();
        	}
        }
#else
        if (status == kStatus_Success)
         {
             if ((driver_state == kTouch_Down) || (driver_state == kTouch_Contact))
             {
                 // screen is touched, update coords:

                 if (touch_state == TOUCH_STATE_RELEASED)
                 {
                     touch_state = TOUCH_STATE_TOUCHED;
                     gx_send_pen_down_event();
                 }
                 else
                 {
                     // test and send pen drag
                     gx_send_pen_drag_event();
                 }
             }
             else
             {
                 // no touch, check so see if last was touched
                 if (touch_state == TOUCH_STATE_TOUCHED)
                 {
                     touch_state = TOUCH_STATE_RELEASED;
                     gx_send_pen_up_event();
                 }
             }
         }
 #endif
     }
 }

 #if defined(DEMO_PANEL) && (DEMO_PANEL == DEMO_PANEL_RK043FN66HS)

 static void gx_delay(uint32_t ms)
 {
     ULONG ticks;

     /* translate ms into ticks. */
     ticks = (ULONG)(ms * TX_TIMER_TICKS_PER_SECOND) / 1000;

     if (ticks == 0)
     {
         while (0U != (ms--))
         {
             SDK_DelayAtLeastUs(1000U, SystemCoreClock);
         }
     }
     else
     {
         tx_thread_sleep(ticks);
     }
 }

 static void BOARD_PullTouchResetPin(bool pullUp)
 {
     if (pullUp)
     {
         GPIO_PinWrite(BOARD_TOUCH_RST_GPIO, BOARD_TOUCH_RST_PIN, 1);
     }
     else
     {
         GPIO_PinWrite(BOARD_TOUCH_RST_GPIO, BOARD_TOUCH_RST_PIN, 0);
     }
 }

 static void BOARD_ConfigTouchIntPin(gt911_int_pin_mode_t mode)
 {
     if (mode == kGT911_IntPinInput)
     {
         BOARD_TOUCH_INT_GPIO->GDIR &= ~(1UL << BOARD_TOUCH_INT_PIN);
     }
     else
     {
         if (mode == kGT911_IntPinPullDown)
         {
             GPIO_PinWrite(BOARD_TOUCH_INT_GPIO, BOARD_TOUCH_INT_PIN, 0);
         }
         else
         {
             GPIO_PinWrite(BOARD_TOUCH_INT_GPIO, BOARD_TOUCH_INT_PIN, 1);
         }

         BOARD_TOUCH_INT_GPIO->GDIR |= (1UL << BOARD_TOUCH_INT_PIN);
     }
 }
 #endif

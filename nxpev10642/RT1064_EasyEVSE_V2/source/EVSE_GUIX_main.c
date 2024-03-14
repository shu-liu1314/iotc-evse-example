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

/* This is a small demo of the high-performance GUIX graphical user interface engine.
   It includes examples of eight
   threads of different priorities, using a message queue, semaphore, mutex, event flags group,
   byte pool, and block pool. Please refer to Chapter 6 of the ThreadX User Guide for a complete
   description of this demonstration.  */

#include <EVSE_GUIX_main.h>
#include "tx_api.h"
#include "gx_api.h"

#include "fsl_debug_console.h"

#include "pin_mux.h"
#include "board.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define BUFFER_SIZE     (50 * 1024)
#define MAX_SLIDER_VAL_TEXT_LENGTH 10
/*******************************************************************************
 * Variables
 ******************************************************************************/

/* a byte pool used for dynamic image rotation */
TX_BYTE_POOL graphics_pool;

/* Allocate for ThreadX byte pool. */
GX_COLOR scratchpad[BUFFER_SIZE / sizeof(GX_COLOR)];
GX_WINDOW_ROOT *root;

GX_STRING nfc_data;
char data_string[20];
GX_STRING evse_data;
static GX_CHAR slider_val_text[MAX_SLIDER_VAL_TEXT_LENGTH + 1];
char my_string[20];
extern uint32_t Temperature;
extern uint32_t GridPowerLimit;
extern float TariffCost;
extern uint32_t EvseRating;
extern char EvseId[9];              /* charging station SN as Hex string */
extern char VehicleId[20];           /* Id of vehicle read from tag */
extern float ChargeCost;            /* Cumulative cost of charge */
extern char ChargeStatus;           /* Character representation of charge eg A to F */
extern uint32_t Battery;                 /* Battery charge level expressed as % */
extern float irms;                  /* meter measured consumption current */
extern float vrms;                  /* meter measured voltage */
extern float kwh;                   /* meter measured power */
extern char EVSE_State[7];          /* Status of charging sequence at Meter */
extern bool new_meterdata;
extern bool vehicleauthentic;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
extern void gx_lcd_board_setup(void);
extern UINT gx_display_driver_imxrt10xx_565rgb_setup(GX_DISPLAY *display);
extern void meter_request_now(void);
void guix_startup(void);
/* Display driver entry point, included in gx.a library */
VOID start_touch_thread(VOID);

/*******************************************************************************
 * Code
 ******************************************************************************/

/* Define main entry point.  */
int guix_main(VOID)
{
    /* perform LCD initialization */
    gx_lcd_board_setup();

    return 0;
}

/******************************************************************************************/
/* Define memory allocator function.                                                     */
/******************************************************************************************/
VOID *memory_allocate(ULONG size)
{
   VOID *memptr;

    if (tx_byte_allocate(&graphics_pool, &memptr, size, TX_NO_WAIT) == TX_SUCCESS)
    {
        return memptr;
    }
    return NULL;
}

/******************************************************************************************/
/* Define memory de-allocator function.                                                   */
/******************************************************************************************/
void memory_free(VOID *mem)
{
    tx_byte_release(mem);
}

/* Define what the initial system looks like.  */

void guix_tx_application_define(void *first_unused_memory)
{
    /* create byte pool. */
    tx_byte_pool_create(&graphics_pool, "scratchpad", scratchpad, BUFFER_SIZE);

    guix_startup();
    //start_touch_thread();
}

void guix_startup(void)
{
    /* Initialize GUIX. */
    gx_system_initialize();

    /* install our memory allocator and de-allocator */
    gx_system_memory_allocator_set(memory_allocate, memory_free);

    /* Instantiate16 bpp 5:6:5 format display driver */
    gx_studio_display_configure(DISPLAY_1, gx_display_driver_imxrt10xx_565rgb_setup, LANGUAGE_ENGLISH,
                                DISPLAY_1_THEME_1, &root);

    gx_canvas_hardware_layer_bind(root->gx_window_root_canvas, 0);

    /* Create the main screen and attach it to root window. */
    gx_studio_named_widget_create("Main_Screen", (GX_WIDGET *)root, GX_NULL);

    /* Create Car window. */
    gx_studio_named_widget_create("CAR_Screen", GX_NULL, GX_NULL);

    /* Create EVSE window. */
    gx_studio_named_widget_create("EVSE_Window", GX_NULL, GX_NULL);

    /* Create Meter window. */
    gx_studio_named_widget_create("Meter_Screen", GX_NULL, GX_NULL);

    /* Create NFC window. */
    gx_studio_named_widget_create("NFC_Screen", GX_NULL, GX_NULL);

    /* Show the root window to make it and main screen visible.  */
    gx_widget_show(root);

    /* Let GUIX run */
    gx_system_start();
}

UINT string_length_get(GX_CONST GX_CHAR *input_string, UINT max_string_length)
{
    UINT length = 0;

    if (input_string)
    {
        /* Traverse the string.  */
        for (length = 0; input_string[length]; length++)
        {
            /* Check if the string length is bigger than the max string length.  */
            if (length >= max_string_length)
            {
                break;
            }
        }
    }

    return length;
}

/* Custom event handler for NFC Screen */
UINT NFC_Event_Process(GX_WINDOW *widget, GX_EVENT *event_ptr)
{

	switch (event_ptr->gx_event_type)
	{
 	  case GX_SIGNAL(ID_Readbtn, GX_EVENT_CLICKED):
		memset(data_string, '\0', sizeof(data_string));
 	    strcpy(data_string,VehicleId);
 	    nfc_data.gx_string_ptr = data_string;
 	    nfc_data.gx_string_length  = strlen(data_string);
 	    gx_prompt_text_set_ext(&NFC_Screen.NFC_Screen_NFC_Screen_prompt_4,&nfc_data);
 	    break;
	  default:
	    gx_window_event_process(widget, event_ptr);
	}
 return 0;
}



/*****************************************************************************/
/* Update slider value.                                                      */
/*****************************************************************************/
void slider_value_update(GX_EVENT *event_ptr)
{
    INT pos;
    GX_STRING string;

    string.gx_string_ptr = slider_val_text;
    pos = event_ptr->gx_event_payload.gx_event_longdata;
    gx_progress_bar_value_set(&CAR_Screen.CAR_Screen_pixelmap_slider_1, pos);
    gx_numeric_prompt_value_set(&CAR_Screen.CAR_Screen_prompt_12, pos);
    Battery = pos;

}


/* Custom event handler for CAR Screen */
UINT slider_event_process(GX_WINDOW *widget, GX_EVENT *event_ptr)
{
	switch (event_ptr->gx_event_type)
	{
	  case GX_SIGNAL(ID_Battery_slider, GX_EVENT_SLIDER_VALUE):
        /* propogate this slider value to the progress bar */
        slider_value_update(event_ptr);
        break;
	  default:
	    gx_window_event_process(widget, event_ptr);
	}
}


void Update_EVSE_Values(void)
{
	UINT status;

	 status = gx_numeric_prompt_value_set(&EVSE_Window.EVSE_Window_prompt_13_2, Temperature);
	 status = gx_numeric_prompt_value_set(&EVSE_Window.EVSE_Window_prompt_13, GridPowerLimit);
	 status = gx_numeric_prompt_value_set(&EVSE_Window.EVSE_Window_prompt_13_1, EvseRating);

	 memset(my_string, '\0', sizeof(my_string));
	 strcpy(my_string, EvseId);
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&EVSE_Window.EVSE_Window_prompt_12, &evse_data);

	 memset(my_string, '\0', sizeof(my_string));
	 strcpy(my_string, VehicleId);
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&CAR_Screen.CAR_Screen_prompt_14, &evse_data);

	 memset(my_string, '\0', sizeof(my_string));
	 status = sprintf(my_string,"%.2f", ChargeCost);
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&EVSE_Window.EVSE_Window_prompt_12_3, &evse_data);

	 if (ChargeStatus == 'C')     /* EV Charging */
	 {
		status = gx_button_select(&EVSE_Window.EVSE_Window_radio_button);
	 } else
	 {
		status = gx_button_deselect(&EVSE_Window.EVSE_Window_radio_button, GX_TRUE);
	 }

	 memset(my_string, '\0', sizeof(my_string));
	 if (vehicleauthentic)
	 {
		 strcpy(my_string, "PASS");
	 } else
	 {
		 strcpy(my_string, "FAIL");
	 }
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&EVSE_Window.EVSE_Window_prompt_12_2, &evse_data);

	 /* Force immediate redraw operation. */
	 status = gx_system_canvas_refresh();

}


void Update_Meter_Values(void)
{
	UINT status;

	 while (!(new_meterdata))
		{
		/* wait until meter data is received and then update */
		}
	 /* convert Voltage float to string to display in GUIX prompt */
	 memset(my_string, '\0', sizeof(my_string));
	 status = sprintf(my_string,"%.2f", vrms);
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&Meter_Screen.Meter_Screen_prompt_10_3, &evse_data);

	 /* convert Current float to string to display in GUIX prompt */
	 memset(my_string, '\0', sizeof(my_string));
	 status = sprintf(my_string,"%.2f", irms);
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&Meter_Screen.Meter_Screen_prompt_10_2, &evse_data);

	 /* convert Power float to string to display in GUIX prompt */
	 memset(my_string, '\0', sizeof(my_string));
	 status = sprintf(my_string,"%.2f", kwh);
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&Meter_Screen.Meter_Screen_prompt_10_4, &evse_data);

	 /* convert EVSE string to GX String */
	 memset(my_string, '\0', sizeof(my_string));
	 strcpy(my_string, EVSE_State);
	 evse_data.gx_string_ptr = my_string;
	 evse_data.gx_string_length  = strlen(my_string);
	 status = gx_prompt_text_set_ext(&Meter_Screen.Meter_Screen_prompt_10, &evse_data);

	 /* Force immediate redraw operation. */
	 status = gx_system_canvas_refresh();

}

/* Custom event handler for Meter Screen */
UINT Meter_Event_Process(GX_WINDOW *widget, GX_EVENT *event_ptr)
{

	switch (event_ptr->gx_event_type)
	{
 	  case GX_SIGNAL(met_Readbtn, GX_EVENT_CLICKED):
		meter_request_now();
 	    break;
	  default:
	    gx_window_event_process(widget, event_ptr);
	}
 return 0;
}

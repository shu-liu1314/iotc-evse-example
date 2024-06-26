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
/* Copyright 2018-2022 NXP											      */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms. */
/* By expressly accepting such terms or by downloading, installing,       */
/* activating and/or otherwise using the software, you are agreeing that  */
/* you have read, and that you agree to comply with and are bound by,     */
/* such license terms.  If you do not agree to be bound by the applicable */
/* license terms, then you may not retain, install, activate or otherwise */
/* use the software                                                       */
/**************************************************************************/

#include <stdio.h>
#include "fsl_gpio.h"
#include "board.h"
#include "clock_config.h"
#include "board.h"
#include "pin_mux.h"
#include "fsl_common.h"
#include "fsl_elcdif.h"
#include "fsl_debug_console.h"

#include "gx_api.h"
#include "gx_display.h"

#define APP_ELCDIF         LCDIF
#define APP_LCDIF_DATA_BUS kELCDIF_DataBus16Bit

/* Display. */
#define LCD_DISP_GPIO     GPIO1
#define LCD_DISP_GPIO_PIN 2

/* Back light. */
#define LCD_BL_GPIO     GPIO2
#define LCD_BL_GPIO_PIN 31

#define DISPLAY_HEIGHT 272
#define DISPLAY_WIDTH  480
#define APP_HSW        41
#define APP_HFP        4
#define APP_HBP        8
#define APP_VSW        10
#define APP_VFP        4
#define APP_VBP        2
#define APP_POL_FLAGS \
    (kELCDIF_DataEnableActiveHigh | kELCDIF_VsyncActiveLow | kELCDIF_HsyncActiveLow | kELCDIF_DriveDataOnRisingClkEdge)
/* Frame buffer data alignment, for better performance, the LCDIF frame buffer should be 64B align. */

#ifndef APP_LCDIF_DATA_BUS
#define APP_LCDIF_DATA_BUS kELCDIF_DataBus16Bit
#endif

#define FRAME_BUFFER_ALIGN  64
#define FRAME_BUFFER_PIXELS (DISPLAY_HEIGHT * DISPLAY_WIDTH)

static volatile GX_BOOL gx_frame_done = GX_FALSE;
static int visible_frame              = 0;

AT_NONCACHEABLE_SECTION_ALIGN(static USHORT frame_buffer[2][FRAME_BUFFER_PIXELS], FRAME_BUFFER_ALIGN);

/* Enable interrupt. */
static void BOARD_EnableLcdInterrupt(void)
{
    EnableIRQ(LCDIF_IRQn);
}

void APP_LCDIF_IRQHandler(void)
{
    uint32_t intStatus;

    intStatus = ELCDIF_GetInterruptStatus(APP_ELCDIF);

    ELCDIF_ClearInterruptStatus(APP_ELCDIF, intStatus);

    if (intStatus & kELCDIF_CurFrameDone)
    {
        gx_frame_done = GX_TRUE;
    }
}

#if 0
void LCDIF_IRQHandler(void)
{
    APP_LCDIF_IRQHandler();
}
#endif

/* Configure display controller for width, height, buffer format */
static void _gx_config_lcd_mode(void)
{
    const elcdif_rgb_mode_config_t config = {
        .panelWidth    = DISPLAY_WIDTH,
        .panelHeight   = DISPLAY_HEIGHT,
        .hsw           = APP_HSW,
        .hfp           = APP_HFP,
        .hbp           = APP_HBP,
        .vsw           = APP_VSW,
        .vfp           = APP_VFP,
        .vbp           = APP_VBP,
        .polarityFlags = APP_POL_FLAGS,
        .bufferAddr    = (uint32_t)frame_buffer[visible_frame],
        .pixelFormat   = kELCDIF_PixelFormatRGB565,
        .dataBus       = APP_LCDIF_DATA_BUS,
    };

    ELCDIF_RgbModeInit(APP_ELCDIF, &config);

    BOARD_EnableLcdInterrupt();
    ELCDIF_EnableInterrupts(APP_ELCDIF, kELCDIF_CurFrameDoneInterruptEnable);
    NVIC_EnableIRQ(LCDIF_IRQn);
}

static void _gx_init_lcd_pixel_clock(void)
{
    uint32_t videoPllFreq;

    /*
     * Initialize the Video PLL.
     * Video PLL output clock is OSC24M * (loopDivider + (denominator / numerator)) / postDivider = 93MHz.
     */
    clock_video_pll_config_t config = {
        .loopDivider = 31,
        .postDivider = 8,
        .numerator   = 0,
        .denominator = 0,
    };

    CLOCK_InitVideoPll(&config);

    videoPllFreq = CLOCK_GetPllFreq(kCLOCK_PllVideo);

    if (videoPllFreq != 93000000)
    {
        PRINTF("Error: Invalid LCDIF pixel clock source.\r\n");
        while (1)
            ;
    }

    /*
     * 000 derive clock from PLL2
     * 001 derive clock from PLL3 PFD3
     * 010 derive clock from PLL5
     * 011 derive clock from PLL2 PFD0
     * 100 derive clock from PLL2 PFD1
     * 101 derive clock from PLL3 PFD1
     */
    CLOCK_SetMux(kCLOCK_LcdifPreMux, 2);
    CLOCK_SetDiv(kCLOCK_LcdifPreDiv, 4);
    CLOCK_SetDiv(kCLOCK_LcdifDiv, 1);
}

/* Initialize the backlight gpio pin */
static void _gx_init_lcd_pins(void)
{
    volatile uint32_t i = 0x100U;

    gpio_pin_config_t config = {
        kGPIO_DigitalOutput,
        0,
    };

    /* Reset the LCD. */
    GPIO_PinInit(LCD_DISP_GPIO, LCD_DISP_GPIO_PIN, &config);

    GPIO_PinWrite(LCD_DISP_GPIO, LCD_DISP_GPIO_PIN, 0);

    while (i--)
    {
    }

    GPIO_PinWrite(LCD_DISP_GPIO, LCD_DISP_GPIO_PIN, 1);

    /* Backlight. */
    config.outputLogic = 1;
    GPIO_PinInit(LCD_BL_GPIO, LCD_BL_GPIO_PIN, &config);
}

void gx_lcd_board_setup(void)
{
    /* perform LCD initialization */
    _gx_init_lcd_pixel_clock();
    _gx_init_lcd_pins();
    _gx_config_lcd_mode();
}

/* toggle the visible and working frame buffer pointers */
static void _gx_display_driver_imxrt_buffer_toggle(GX_CANVAS *canvas, GX_RECTANGLE *dirty)
{
    GX_RECTANGLE Limit;
    GX_RECTANGLE Copy;
    ULONG offset;
    INT copy_width;
    INT copy_height;
    INT row;
    INT frame_pitch_offset;
    USHORT *get;
    USHORT *put;

    gx_utility_rectangle_define(&Limit, 0, 0, canvas->gx_canvas_x_resolution - 1, canvas->gx_canvas_y_resolution - 1);

    // toggle the visible frame:
    visible_frame ^= 1;
    int working_frame = visible_frame ^ 0x01;

    ELCDIF_SetNextBufferAddr(LCDIF, (uint32_t)frame_buffer[visible_frame]);
    canvas->gx_canvas_memory = (ULONG *)frame_buffer[working_frame];

    // wait for hardware to finish the current frame:

    gx_frame_done = GX_FALSE;
    while (!gx_frame_done)
    {
    }

    /* copy from the newly visible frame to the new working frame */

    if (gx_utility_rectangle_overlap_detect(&Limit, &canvas->gx_canvas_dirty_area, &Copy))
    {
        /* copy modified portion from visible frame to working frame */
        copy_width  = Copy.gx_rectangle_right - Copy.gx_rectangle_left + 1;
        copy_height = Copy.gx_rectangle_bottom - Copy.gx_rectangle_top + 1;

        offset = Copy.gx_rectangle_top * canvas->gx_canvas_x_resolution;
        offset += Copy.gx_rectangle_left;

        get = frame_buffer[visible_frame];
        get += offset;

        // offset by dirty rect pos
        put = (USHORT *)canvas->gx_canvas_memory;

        // offset by canvas offset:
        offset = (canvas->gx_canvas_display_offset_y + Copy.gx_rectangle_top) * canvas->gx_canvas_x_resolution;
        offset += canvas->gx_canvas_display_offset_x + Copy.gx_rectangle_left;
        put += offset;

        frame_pitch_offset = canvas->gx_canvas_x_resolution;

        for (row = 0; row < copy_height; row++)
        {
            memcpy(put, get, copy_width * 2);
            put += frame_pitch_offset;
            get += frame_pitch_offset;
        }
    }
}

static UINT _gx_imxrt_graphics_layer_initialize(INT layer, GX_CANVAS *canvas)
{
    int working_frame             = visible_frame ^ 0x1;
    canvas->gx_canvas_memory      = (ULONG *)frame_buffer[working_frame];
    canvas->gx_canvas_memory_size = sizeof(frame_buffer[0]);
    return GX_SUCCESS;
}

static GX_DISPLAY_LAYER_SERVICES gx_imxrt_graphics_layer_services = {
    _gx_imxrt_graphics_layer_initialize,
    GX_NULL, // GraphicsLayerShow,
    GX_NULL, // GraphicsLayerHide,
    GX_NULL, // GraphicsLayerAlphaSet,
    GX_NULL, // GraphicsLayerPosSet
};

UINT gx_display_driver_imxrt10xx_565rgb_setup(GX_DISPLAY *display)
{
    _gx_display_driver_565rgb_setup(display, GX_NULL, _gx_display_driver_imxrt_buffer_toggle);

    // configure canvas binding functions:
    display->gx_display_layer_services = &gx_imxrt_graphics_layer_services;

    memset(frame_buffer, 0, sizeof(frame_buffer));
    ELCDIF_RgbModeStart(LCDIF);

    return GX_SUCCESS;
}

/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_port.h"
#include "clock_config.h"
#include "pin_mux.h"

#include "slcd_engine.h"
#include "fsl_slcd.h"

#include "fsl_adc16.h"

#include "fsl_lptmr.h"

#include "fsl_qtmr.h"

#include <math.h>
#include "fraclib.h"
#include "meterlib.h"
#include "meterlib1ph_cfg.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define offLow32Pin(n) ((uint32_t)1 << (n))       /* Pin offset for the low 32 pins. */
#define offHigh32Pin(n) ((uint32_t)1 << (n - 32)) /* Pin offset for the high 32 pins. */
#define SLCD_INVALIDINPUT (-1)                    /* Invalid input. */
#define SLCD_OK (0)                               /* Execute success. */

#define DEMO_ADC16_BASEADDR ADC0
#define DEMO_ADC16_CHANNEL_GROUP 0U
#define DEMO_ADC16_USER_CHANNEL 8U

/* Low Power Timer */
#define LPTMR_CLK_FREQ CLOCK_GetFreq(kCLOCK_LpoClk)
#define LPTMR0_IRQHandler LPTMR0_LPTMR1_IRQHandler

#define _PI   3.14159265358979323846	/* pi */

#define BUS_CLK_FREQ CLOCK_GetFreq(kCLOCK_BusClk)

/* GPIO and SW1 */
#define BOARD_SW_GPIO        BOARD_SW1_GPIO
#define BOARD_SW_PORT        BOARD_SW1_PORT
#define BOARD_SW_GPIO_PIN    BOARD_SW1_GPIO_PIN
#define BOARD_SW_IRQ         BOARD_SW1_IRQ
#define BOARD_SW_IRQ_HANDLER BOARD_SW1_IRQ_HANDLER

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*!
 * @brief SLCD set lcd pins.
 *
 * @param type lcd setting type @ref "lcd_set_type_t".
 * @param lcd_pin lcd pin.
 * @param pin_val pin setting value.
 * @param on The display on/off flag.
 */
static void SLCD_SetLCDPin(lcd_set_type_t type, uint32_t lcd_pin, uint8_t pin_val, int32_t on);

/*!
 * @brief SLCD Application Initialization.
 */
static void SLCD_APP_Init(void);

/*!
 * @brief SLCD Clear Screen.
 */
static void SLCD_Clear_Screen(void);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* LCD segment pin and slcd gpio pin number map. */
static uint8_t slcd_lcd_gpio_seg_pin[SLCD_PIN_NUM] = {38, 36, 34, 32, 31, 29, 25, 23, 43, 37,
                                                      35, 33, 50, 30, 45, 24, 26, 28, 44, 59};
volatile uint32_t adcResultValue = 0U;
static uint32_t tmp32;
volatile static uint16_t tmp16;
static uint8_t  tmpnum;
lptmr_config_t lptmrConfig;
adc16_config_t adc16ConfigStruct;
adc16_channel_config_t adc16ChannelConfigStruct;
float Pot_Value;  // Potentiometer reading on TWR board scaled to 32A
float RMS_Voltage; // calculated voltage

tSLCD_Engine slcd_engine;

static tMETERLIB1PH_DATA mlib = METERLIB1PH_CFG;
static volatile frac32  u24_sample, i24_sample;
static tENERGY_CNT wh_cnt, varh_cnt;
static double  time = 0.0, U_RMS, I_RMS, P, Q, S, U_ANGLE = (45.0/180.0)*_PI,
                                                  I_SHIFT = (-5.5/180.0)*_PI;
static int     cycle = 0;
static frac16  shift = METERLIB_DEG2SH(-5.5, 50.0);
static uint8_t State_Counter = 0;               /* States are 1: State A Not Connected 2: State B Connected Ready 3: State C Charging 4: Vent*/
static uint8_t Error_Counter = 0;               /* States are 0: no error 1: State E Error 2: State F Error */

/* Whether the SW button is pressed */
volatile bool g_Button1Press = false;
volatile bool g_Button2Press = false;
volatile uint8_t led_turn = 0;

volatile bool PWMRunning = false;

static char Status_String[7] = "STATEA";
float Status_Index = 1.0;

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Interrupt service function of switch.
 *
 * This function is called when SW1 or SW2 is pressed
 *  */
void BOARD_SW1_IRQ_HANDLER(void)
{
	/* Check which SW was pressed by testing each port ISR register */
	if ((GPIO_PortGetInterruptFlags(BOARD_SW1_GPIO) && (1U << BOARD_SW1_GPIO_PIN)) > 0)
	 {
	    /* Clear external interrupt flag. */
	    GPIO_PortClearInterruptFlags(BOARD_SW1_GPIO, 1U << BOARD_SW1_GPIO_PIN);
        /* Send Status. */
        switch (State_Counter)
        {
        case 0:
        	  strcpy(Status_String, "STATEA");
        	  Status_Index = 1.0;
        	  PRINTF("%1.1f[4]\r", Status_Index);
        	  PWM_OnOFF(0, 53);
        	  GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
        	  GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
        	  GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
        	  g_Button1Press = false;
        	  Error_Counter = 0;
        	  break;
        case 1:
        	  strcpy(Status_String, "STATEB");
        	  Status_Index = 2.0;
        	  PRINTF("%1.1f[4]\r", Status_Index);
        	  PWM_OnOFF(0, 53);
         	  GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortClear(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
        	  g_Button1Press = false;
        	  break;
        case 2:
        	  strcpy(Status_String, "STATEC");
        	  Status_Index = 3.0;
        	  PRINTF("%1.1f[4]\r", Status_Index);
        	  PWM_OnOFF(1, 53);
      	    /* Change state of button. */
        	  GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
        	  led_turn = 0;
      	      g_Button1Press = true;
        	  break;
        case 3:
        	  strcpy(Status_String, "STATED");
        	  Status_Index = 4.0;
        	  PRINTF("%1.1f[4]\r", Status_Index);
        	  PWM_OnOFF(0, 53);
      	    /* Change state of button. */
        	  GPIO_PortClear(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortClear(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
      	      g_Button1Press = false;
        	  break;
        default:
        	  break;
        }
        State_Counter++;
        State_Counter %= 4;

	 }
	if ((GPIO_PortGetInterruptFlags(BOARD_SW2_GPIO) && (1U << BOARD_SW2_GPIO_PIN)) > 0)
	 {
	    /* Clear external interrupt flag. */
	    GPIO_PortClearInterruptFlags(BOARD_SW2_GPIO, 1U << BOARD_SW2_GPIO_PIN);
	    /* Change state of button. */
	    g_Button2Press = true;
	    /* reset charge state */
	    State_Counter = 0;
        Error_Counter++;
         if (Error_Counter>2) Error_Counter = 0;
        /* Send Status. */
        switch (Error_Counter)
        {
        case 0:
        	  GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
        	  break;
        case 1:
        	  strcpy(Status_String, "STATEE");
        	  Status_Index = 5.0;
        	  PRINTF("%1.1f[4]\r", Status_Index);
        	  PWM_OnOFF(0, 80);
        	  GPIO_PortClear(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
        	  g_Button1Press = false;
        	  break;
        case 2:
        	  strcpy(Status_String, "STATEF");
        	  Status_Index = 6.0;
        	  PRINTF("%1.1f[4]\r", Status_Index);
        	  PWM_OnOFF(0, 80);
          	  GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
          	  GPIO_PortClear(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
        	  g_Button1Press = false;
        	  break;
        default:
        	  break;
        }
	 }
    SDK_ISR_EXIT_BARRIER;
}

static void SLCD_SetLCDPin(lcd_set_type_t type, uint32_t lcd_pin, uint8_t pin_val, int32_t on)
{
    assert(lcd_pin > 0);

    uint8_t gpio_pin = 0;
    uint8_t bit_val = 0;
    uint8_t i = 0;

    /* lcd _pin starts from 1. */
    gpio_pin = slcd_lcd_gpio_seg_pin[lcd_pin - 1];

    if (type == SLCD_Set_Num)
    {
        SLCD_SetFrontPlaneSegments(LCD, gpio_pin, (on ? pin_val : 0));
    }
    else
    {
        for (i = 0; i < 8; ++i)
        {
            bit_val = (uint8_t)(pin_val >> i) & 0x1U;
            if (bit_val)
            {
                SLCD_SetFrontPlaneOnePhase(LCD, gpio_pin, (slcd_phase_index_t)i, on);
            }
        }
    }
}

static void SLCD_APP_Init(void)
{
    slcd_config_t config;
    slcd_clock_config_t clkConfig =
    {
        kSLCD_DefaultClk,
        kSLCD_AltClkDivFactor1,
        kSLCD_ClkPrescaler01,
    };

    /* Get Default configuration. */
    /*
     * config.displayMode = kSLCD_NormalMode;
     * config.powerSupply = kSLCD_InternalVll3UseChargePump;
     * config.voltageTrim = kSLCD_RegulatedVolatgeTrim00;
     * config.lowPowerBehavior = kSLCD_EnabledInWaitStop;
     * config.frameFreqIntEnable = false;
     * config.faultConfig = NULL;
     */
    SLCD_GetDefaultConfig(&config);

    /* Verify and Complete the configuration structure. */
    config.clkConfig = &clkConfig;
    config.loadAdjust = kSLCD_HighLoadOrSlowestClkSrc;
    config.dutyCycle = kSLCD_1Div8DutyCycle;
    /* LCD_P31/P30/P29/P28/P26/P25/P24/P23/P22/P20/P19/P14/P13. */
    config.slcdLowPinEnabled =
        (offLow32Pin(14) | offLow32Pin(20) | offLow32Pin(22) | offLow32Pin(13) | offLow32Pin(19) | offLow32Pin(28) |
         offLow32Pin(26) | offLow32Pin(24) | offLow32Pin(31) | offLow32Pin(29) | offLow32Pin(25) | offLow32Pin(23) |
         offLow32Pin(30));
    /* LCD_P59/P58/P57/P56/P50/P45/P44/P43/P38/P37/P36/P35/P34/P33/P32. */
    config.slcdHighPinEnabled =
        (offHigh32Pin(56) | offHigh32Pin(58) | offHigh32Pin(57) | offHigh32Pin(59) | offHigh32Pin(44) |
         offHigh32Pin(45) | offHigh32Pin(38) | offHigh32Pin(36) | offHigh32Pin(34) | offHigh32Pin(32) |
         offHigh32Pin(43) | offHigh32Pin(37) | offHigh32Pin(35) | offHigh32Pin(33) | offHigh32Pin(50));
    /* LCD_P22/20/19/14/13 --> b22/b20/b19/b14/b13 = 1. */
    config.backPlaneLowPin = (offLow32Pin(14) | offLow32Pin(20) | offLow32Pin(22) | offLow32Pin(13) | offLow32Pin(19));
    /* LCD_P58/57/56 --> b26/b25/b24 = 1. */
    config.backPlaneHighPin = (offHigh32Pin(56) | offHigh32Pin(58) | offHigh32Pin(57));
    SLCD_Init(LCD, &config);
}

static void SLCD_Clear_Screen(void)
{
    /* Disables all front plane pins on all eight phases Phase A ~ Phase H.
    P59/P50/P45/P44/P43/P38/P37/P36/P35/P34/P33/P32/P31/P30/P29/P28/P26/P25/P24/P23 */
    SLCD_SetFrontPlaneSegments(LCD, 23, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 24, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 25, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 26, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 28, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 29, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 30, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 31, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 32, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 33, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 34, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 35, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 36, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 37, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 38, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 43, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 44, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 45, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 50, kSLCD_NoPhaseActivate);
    SLCD_SetFrontPlaneSegments(LCD, 59, kSLCD_NoPhaseActivate);
}



static void SLCD_Set_Display_Ready(tSLCD_Engine *slcd_engine)
{
    uint32_t pinNum = 0;
    uint32_t allPhaseOn = kSLCD_PhaseAActivate | kSLCD_PhaseBActivate | kSLCD_PhaseCActivate | kSLCD_PhaseDActivate |
                          kSLCD_PhaseEActivate | kSLCD_PhaseFActivate | kSLCD_PhaseGActivate | kSLCD_PhaseHActivate;

    for (pinNum = 0; pinNum < FSL_FEATURE_SLCD_HAS_PIN_NUM; pinNum++)
    {
        SLCD_SetFrontPlaneSegments(LCD, pinNum, allPhaseOn);
    }

    SLCD_SetBackPlanePhase(LCD, 14, kSLCD_PhaseHActivate);
    SLCD_SetBackPlanePhase(LCD, 20, kSLCD_PhaseGActivate);
    SLCD_SetBackPlanePhase(LCD, 22, kSLCD_PhaseFActivate);
    SLCD_SetBackPlanePhase(LCD, 56, kSLCD_PhaseEActivate);
    SLCD_SetBackPlanePhase(LCD, 58, kSLCD_PhaseDActivate);
    SLCD_SetBackPlanePhase(LCD, 13, kSLCD_PhaseCActivate);
    SLCD_SetBackPlanePhase(LCD, 19, kSLCD_PhaseBActivate);
    SLCD_SetBackPlanePhase(LCD, 57, kSLCD_PhaseAActivate);

    SLCD_StartDisplay(LCD);
    SLCD_Clear_Screen();
    SLCD_Engine_Show_Icon(slcd_engine, ICON_L1, 1);
//    SLCD_Engine_Show_Icon(slcd_engine, ICON_RMS, 1);
    SLCD_Engine_Show_Icon(slcd_engine, ICON_S16, 1);
    SLCD_Engine_Show_Icon(slcd_engine, ICON_S33, 1);
    SLCD_Engine_Show_Icon(slcd_engine, ICON_P3, 1);
}

static void Run_MeterLib(void)
{
    /* calculate phase voltage and phase current waveforms                    */
    time = time+(1.0/KWH_CALC_FREQ);
    // simulated calculated voltage waveform
    u24_sample = FRAC24(((sin(2*_PI*50.0*time+U_ANGLE)*230.0*sqrt(2)+0.0)/U_MAX));

    /* simulated calculated current waveform */
    /* Calculate current sample based on Pot reading */
    i24_sample = FRAC24(((sin(2*_PI*50.0*time+I_SHIFT)*(Pot_Value)*sqrt(2)+0.0)/I_MAX));

    METERLIB1PH_ProcSamples(&mlib,u24_sample,i24_sample,&shift);
    METERLIB1PH_CalcWattHours(&mlib,&wh_cnt,METERLIB_KWH_PR(IMP_PER_KWH));

    /* functions below might be called less frequently - please refer to      */
    /* KWH_CALC_FREQ, KVARH_CALC_FREQ and DECIM_FACTOR constants              */
    if (!(cycle % (int)(KWH_CALC_FREQ/KVARH_CALC_FREQ)))
    {
      METERLIB1PH_CalcVarHours (&mlib,&varh_cnt,METERLIB_KVARH_PR(IMP_PER_KVARH));
    }

    if (!(cycle % DECIM_FACTOR))
    {
      METERLIB1PH_CalcAuxiliary(&mlib);
    }

    METERLIB1PH_ReadResults (&mlib,&U_RMS,&I_RMS,&P,&Q,&S);
    //    PRINTF("\r\nSample Count: %d \r\n", cycle);
    //    PRINTF("Current Sample Value: %4.2f \r\n", F32TODBL(i24_sample));
    //    PRINTF("Voltage Sample Value: %5.2f \r\n", F32TODBL(u24_sample));
    //    PRINTF("RMS :%3.2f V ", U_RMS);
    //    PRINTF("RMS :%3.2f A \r\n", I_RMS);
    //    PRINTF("Active Power Value: %4.3f W\r\n", P);
    //    PRINTF("Re-Active Power Value: %4.3f VAr\r\n", Q);
    //    PRINTF("Apparent Power Value: %4.3f VA\r\n", S);
    //    PRINTF("%d,%3.6f,%3.6f,%3.2f,%3.2f,%4.3f,%4.2f,%4.2f\r\n",
    //       		cycle, F32TODBL(i24_sample), F32TODBL(u24_sample), U_RMS, I_RMS, P, Q, S);

        cycle++;
}

/*
 * Timer handler to sequence LED blink Rate and LCD refresh rate
 */
void LPTMR0_IRQHandler(void)
{
    LPTMR_ClearStatusFlags(LPTMR0, kLPTMR_TimerCompareFlag);

    tmpnum = (uint8_t)(tmp32/1000);
    tmp32 = tmp32 % 1000;
    SLCD_Engine_Show_Num(&slcd_engine, tmpnum, NUM_POS5, 1);

    tmpnum = (uint8_t)(tmp32/100);
    tmp32 = tmp32 % 100;
    SLCD_Engine_Show_Num(&slcd_engine, tmpnum, NUM_POS6, 1);

    tmpnum = (uint8_t)(tmp32/10);
    tmp32 = tmp32 % 10;
    SLCD_Engine_Show_Num(&slcd_engine, tmpnum, NUM_POS7, 1);

    tmpnum = (uint8_t)(tmp32);
    SLCD_Engine_Show_Num(&slcd_engine, tmpnum, NUM_POS8, 1);

    tmpnum = Status_Index / 1;
    SLCD_Engine_Show_Num(&slcd_engine, tmpnum, NUM_POS15, 1);

    if ((Error_Counter==1) || (Error_Counter==2))
    {
    	SLCD_Engine_Show_Icon(&slcd_engine, ICON_S29, 1);
    }
    SLCD_Engine_Show_Icon(&slcd_engine, ICON_L1, 1);

    if (g_Button1Press)
    {
        /* Toggle LED. */
        switch (led_turn)
        {
        case 0:
        	  GPIO_PortClear(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
		      break;
        case 1:
      	      GPIO_PortClear(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortClear(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
        	  break;
        case 2:
    	      GPIO_PortClear(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortClear(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortClear(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
		      break;
        case 3:
    	      GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
              GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
		      break;
        default:
        	  break;
        }
        led_turn++;
        if (led_turn>3) led_turn = 0;
    }

}

/*
 * LPTMR is used to create refresh timing for the onboard LCD
 */
static void Start_Timer(void)
{
    /* Configure LPTMR */
    /*
     * lptmrConfig.timerMode = kLPTMR_TimerModeTimeCounter;
     * lptmrConfig.pinSelect = kLPTMR_PinSelectInput_0;
     * lptmrConfig.pinPolarity = kLPTMR_PinPolarityActiveHigh;
     * lptmrConfig.enableFreeRunning = false;
     * lptmrConfig.bypassPrescaler = true;
     * lptmrConfig.prescalerClockSource = kLPTMR_PrescalerClock_1;
     * lptmrConfig.value = kLPTMR_Prescale_Glitch_0;
     */
    LPTMR_GetDefaultConfig(&lptmrConfig);
    /* Initialise the lptmr */
    LPTMR_Init(LPTMR0, &lptmrConfig);

    /* Set timer period */
    /* set LPTMR to 10mS interval */
    LPTMR_SetTimerPeriod(LPTMR0, USEC_TO_COUNT(750000u, LPTMR_CLK_FREQ));
    /* Enable timer interrupt */
    LPTMR_EnableInterrupts(LPTMR0, kLPTMR_TimerInterruptEnable);

    /* Enable at the NVIC */
    EnableIRQ(LPTMR0_LPTMR1_IRQn);
    LPTMR_StartTimer(LPTMR0);
}


/*
 * Measure R21 value connected to the 16 bit ADC channel 8
 */
static void Start_Potentiometer(void)
{
    /*
     * adc16ConfigStruct.referenceVoltageSource = kADC16_ReferenceVoltageSourceVref;
     * adc16ConfigStruct.clockSource = kADC16_ClockSourceAsynchronousClock;
     * adc16ConfigStruct.enableAsynchronousClock = true;
     * adc16ConfigStruct.clockDivider = kADC16_ClockDivider8;
     * adc16ConfigStruct.resolution = kADC16_ResolutionSE12Bit;
     * adc16ConfigStruct.longSampleMode = kADC16_LongSampleDisabled;
     * adc16ConfigStruct.enableHighSpeed = false;
     * adc16ConfigStruct.enableLowPower = false;
     * adc16ConfigStruct.enableContinuousConversion = false;
     */
    ADC16_GetDefaultConfig(&adc16ConfigStruct);
    adc16ConfigStruct.clockDivider = kADC16_ClockDivider2;
    ADC16_Init(DEMO_ADC16_BASEADDR, &adc16ConfigStruct);
    ADC16_EnableHardwareTrigger(DEMO_ADC16_BASEADDR, false); /* Make sure the software trigger is used. */
    ADC16_SetHardwareAverage(DEMO_ADC16_BASEADDR, kADC16_HardwareAverageCount8 );
    if (kStatus_Success == ADC16_DoAutoCalibration(DEMO_ADC16_BASEADDR))
    {
       // PRINTF("ADC16_DoAutoCalibration() Done.\r\n");
    }
    else
    {
      //  PRINTF("ADC16_DoAutoCalibration() Failed.\r\n");
    }

    adc16ChannelConfigStruct.channelNumber = DEMO_ADC16_USER_CHANNEL;
    adc16ChannelConfigStruct.enableInterruptOnConversionCompleted = false;
    /*
     When in software trigger mode, each conversion is launched once calling the "ADC16_SetChannelConfig()"
     function, which works like writing a conversion command and executing it.
     For another channel's conversion, just to change the "channelNumber" field in channel's configuration
     structure, and call the ADC16_SetChannelConf() again.
    */
    ADC16_SetChannelConfig(DEMO_ADC16_BASEADDR, DEMO_ADC16_CHANNEL_GROUP, &adc16ChannelConfigStruct);

    while (0U == (kADC16_ChannelConversionDoneFlag &
                  ADC16_GetChannelStatusFlags(DEMO_ADC16_BASEADDR, DEMO_ADC16_CHANNEL_GROUP)))
    {
    }
}


/*
 * Monitor UART RX for valid commands from Host
 */
static void Process_HostCommand(void)
{
	  char ch_in;
	  uint8_t loop;

      loop = 1;
	  while(loop)
	  {
       ch_in = GETCHAR();

	    if ((ch_in<'0') || (ch_in>'F'))
	    {
	      /* command received is invalid, restart while loop immediately*/
	      continue;
	    }

	    switch (ch_in)
	        {
	        case '0':
	        	PRINTF("%3.2f[1]%3.2f[2]%4.2f[3]%1.1f[4]\r", I_RMS, U_RMS, P, Status_Index);
	        	loop = 0;
	            break;
	        case '1':
	        	PRINTF("%3.2f[1]\r", I_RMS);
	        	loop = 0;
	            break;
	        case '2':
	        	PRINTF("%3.2f[2]\r", U_RMS);
	        	loop = 0;
	            break;
	        case '3':
	        	PRINTF("%4.2f[3]\r", P);
	        	loop = 0;
	            break;
	        case '4':
	        	PRINTF("%1.1f[4]\r", Status_Index);
	        	loop = 0;
	            break;
	        case 'A':
  			    strcpy(Status_String, "STATEA");
			    Status_Index = 1.0;
			    PWM_OnOFF(0, 53);
			    GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
			    GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
			    GPIO_PortSet(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
			    State_Counter = 1;
			    Error_Counter = 0;
                g_Button1Press = false;
	        	loop = 0;
	            break;
	        case 'B':
                Status_Index = 2; //STATEB
          	    strcpy(Status_String, "STATEB");
           	    PWM_OnOFF(0, 53);
            	GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
                GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
                GPIO_PortClear(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
                State_Counter = 2;
                g_Button1Press = false;
	        	loop = 0;
	            break;
	        case 'C':
                Status_Index = 3; //STATEC
          	    strcpy(Status_String, "STATEC");
          	    PWM_OnOFF(1, 53);
        	    /* Change state of button. */
          	    GPIO_PortSet(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
          	    led_turn = 0;
          	    g_Button1Press = true;
          	    State_Counter = 3;
	        	loop = 0;
	            break;
	        case 'D':
                Status_Index = 4; //STATED
          	    strcpy(Status_String, "STATED");
          	    PWM_OnOFF(0, 53);
        	    /* Change state of button. */
          	    GPIO_PortClear(BOARD_INITPINS_LED_ORANGE_GPIO, BOARD_INITPINS_LED_ORANGE_GPIO_PIN_MASK);
                GPIO_PortSet(BOARD_INITPINS_LED_RED_GPIO, BOARD_INITPINS_LED_RED_GPIO_PIN_MASK);
                GPIO_PortClear(BOARD_INITPINS_LED_GREEN_GPIO, BOARD_INITPINS_LED_GREEN_GPIO_PIN_MASK);
                g_Button1Press = false;
                State_Counter = 4;
	        	loop = 0;
	            break;
	        case 'E':
                Status_Index = 5; //STATEE
	        	loop = 0;
	            break;
	        case 'F':
                Status_Index = 6; //STATEF
	        	loop = 0;
	            break;
	        default:
	            /*Execute these statements when the result of expression Not matching with any Option */
	            break;
	        }
	   }
}


/*
 * PWM control used to indicate EVSE current capability to vehicle
 * onoff = 0 then PWM output disabled
 * onoff = 1 then PWM output enabled
 * duty = on time as percentage
 * Only enabled during charge phase
 */
void PWM_OnOFF(uint8_t onoff, uint8_t perc)
{
    qtmr_config_t qtmrConfig;
    /*
     * qtmrConfig.debugMode = kQTMR_RunNormalInDebug;
     * qtmrConfig.enableExternalForce = false;
     * qtmrConfig.enableMasterMode = false;
     * qtmrConfig.faultFilterCount = 0;
     * qtmrConfig.faultFilterPeriod = 0;
     * qtmrConfig.primarySource = kQTMR_ClockDivide_2;
     * qtmrConfig.secondarySource = kQTMR_Counter0InputPin;
     */

    if ((onoff==1) && (PWMRunning == 0))
    {
        QTMR_GetDefaultConfig(&qtmrConfig);
        /* Use IP bus clock div by 8 */
        qtmrConfig.primarySource = kQTMR_ClockDivide_8;
        QTMR_Init(TMR1, &qtmrConfig);
        /* Generate a 1Khz PWM signal with 70% high duty cycle */
        QTMR_SetupPwm(TMR1, 1000, perc, false, BUS_CLK_FREQ / 8);
        /* Start the counter */
        QTMR_StartTimer(TMR1, kQTMR_PriSrcRiseEdge);
        PWMRunning = true;
    }
    if ((onoff == 0) && (PWMRunning == 1))
    {
    	QTMR_StopTimer(TMR1);
    	PWMRunning = false;
    }

}

/*
 * Handler routine used to obtain set value of R21 potentiometer, scale to max current
 * and then use this value when running the metrology library
 * This occurs every 10mS
 */
void SysTick_Handler(void)
{
    /* Obtain latest ADC value */
    while (0U == (kADC16_ChannelConversionDoneFlag &
                  ADC16_GetChannelStatusFlags(DEMO_ADC16_BASEADDR, DEMO_ADC16_CHANNEL_GROUP)))
    {
    }
    tmp16 = ADC16_GetChannelConversionValue(DEMO_ADC16_BASEADDR, DEMO_ADC16_CHANNEL_GROUP);
    /* scaling amps to max 32 */
    tmp32 = (3200 * tmp16) / 4095;
    Pot_Value = (((float)tmp16) / 4095) * 32;
    RMS_Voltage = Pot_Value * 10.0;

    /* start another conversion */
    ADC16_SetChannelConfig(DEMO_ADC16_BASEADDR, DEMO_ADC16_CHANNEL_GROUP, &adc16ChannelConfigStruct);

    Run_MeterLib();
}

/*!
 * @brief main function
 */
int main(void)
{


    /* Init hardware. */
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    /* SLCD Initialisation. */
    SLCD_APP_Init();

    memset(&slcd_engine, 0, sizeof(tSLCD_Engine));
    SLCD_Engine_Init(&slcd_engine, SLCD_SetLCDPin);

    SLCD_Set_Display_Ready(&slcd_engine);
    Start_Potentiometer();
    Start_Timer();

    /* Load Interrupt for board Switches. */
    EnableIRQ(BOARD_SW_IRQ);

    /* Set systick reload value to generate 10ms interrupt */
    if (SysTick_Config(SystemCoreClock / 100U))
    {
        while (1)
        {
         /* arrives here only if Systick could not be setup correctly */
        }
    }

    while (1)
    {
    	Process_HostCommand();
    }
}

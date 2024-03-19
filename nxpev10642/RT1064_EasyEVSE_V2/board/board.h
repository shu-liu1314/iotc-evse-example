/*
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _BOARD_H_
#define _BOARD_H_

#include "clock_config.h"
#include "fsl_common.h"
#include "fsl_gpio.h"
#include "fsl_clock.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @brief The board name */
#define BOARD_NAME "MIMXRT1064-EVK"

/* The UART to use for debug messages. */
#define BOARD_DEBUG_UART_TYPE     kSerialPort_Uart
#define BOARD_DEBUG_UART_BASEADDR (uint32_t) LPUART1
#define BOARD_DEBUG_UART_INSTANCE 1U

#define BOARD_DEBUG_UART_CLK_FREQ BOARD_DebugConsoleSrcFreq()

#define BOARD_UART_IRQ         LPUART1_IRQn
#define BOARD_UART_IRQ_HANDLER LPUART1_IRQHandler

#ifndef BOARD_DEBUG_UART_BAUDRATE
#define BOARD_DEBUG_UART_BAUDRATE (115200U)
#endif /* BOARD_DEBUG_UART_BAUDRATE */

/*! @brief The USER_LED used for board */
#define LOGIC_LED_ON  (0U)
#define LOGIC_LED_OFF (1U)
#ifndef BOARD_USER_LED_GPIO
#define BOARD_USER_LED_GPIO GPIO1
#endif
#ifndef BOARD_USER_LED_GPIO_PIN
#define BOARD_USER_LED_GPIO_PIN (9U)
#endif

#define USER_LED_INIT(output)                                            \
    GPIO_PinWrite(BOARD_USER_LED_GPIO, BOARD_USER_LED_GPIO_PIN, output); \
    BOARD_USER_LED_GPIO->GDIR |= (1U << BOARD_USER_LED_GPIO_PIN) /*!< Enable target USER_LED */
#define USER_LED_ON() \
    GPIO_PortClear(BOARD_USER_LED_GPIO, 1U << BOARD_USER_LED_GPIO_PIN)                  /*!< Turn off target USER_LED */
#define USER_LED_OFF() GPIO_PortSet(BOARD_USER_LED_GPIO, 1U << BOARD_USER_LED_GPIO_PIN) /*!<Turn on target USER_LED*/
#define USER_LED_TOGGLE()                                       \
    GPIO_PinWrite(BOARD_USER_LED_GPIO, BOARD_USER_LED_GPIO_PIN, \
                  0x1 ^ GPIO_PinRead(BOARD_USER_LED_GPIO, BOARD_USER_LED_GPIO_PIN)) /*!< Toggle target USER_LED */

/*! @brief Define the port interrupt number for the board switches */
#ifndef BOARD_USER_BUTTON_GPIO
#define BOARD_USER_BUTTON_GPIO GPIO5
#endif
#ifndef BOARD_USER_BUTTON_GPIO_PIN
#define BOARD_USER_BUTTON_GPIO_PIN (0U)
#endif
#define BOARD_USER_BUTTON_IRQ         GPIO5_Combined_0_15_IRQn
#define BOARD_USER_BUTTON_IRQ_HANDLER GPIO5_Combined_0_15_IRQHandler
#define BOARD_USER_BUTTON_NAME        "SW8"

/*! @brief The board flash size */
#define BOARD_FLASH_SIZE (0x400000U)

/*! @brief The ENET PHY address. */
#define BOARD_ENET0_PHY_ADDRESS (0x02U) /* Phy address of enet port 0. */

/* USB PHY condfiguration */
#define BOARD_USB_PHY_D_CAL     (0x0CU)
#define BOARD_USB_PHY_TXCAL45DP (0x06U)
#define BOARD_USB_PHY_TXCAL45DM (0x06U)

#define BOARD_ARDUINO_INT_IRQ   (GPIO1_INT3_IRQn)
#define BOARD_ARDUINO_I2C_IRQ   (LPI2C1_IRQn)
#define BOARD_ARDUINO_I2C_INDEX (1)

/* @Brief Board accelerator sensor configuration */
#define BOARD_ACCEL_I2C_BASEADDR LPI2C1
/* Select USB1 PLL (480 MHz) as LPI2C's clock source */
#define BOARD_ACCEL_I2C_CLOCK_SOURCE_SELECT (0U)
/* Clock divider for LPI2C clock source */
#define BOARD_ACCEL_I2C_CLOCK_SOURCE_DIVIDER (5U)
#define BOARD_ACCEL_I2C_CLOCK_FREQ           (CLOCK_GetFreq(kCLOCK_Usb1PllClk) / 8 / (BOARD_ACCEL_I2C_CLOCK_SOURCE_DIVIDER + 1U))

#define BOARD_CODEC_I2C_BASEADDR             LPI2C1
#define BOARD_CODEC_I2C_INSTANCE             1U
#define BOARD_CODEC_I2C_CLOCK_SOURCE_SELECT  (0U)
#define BOARD_CODEC_I2C_CLOCK_SOURCE_DIVIDER (5U)
#define BOARD_CODEC_I2C_CLOCK_FREQ           (10000000U)

/* @Brief Board CAMERA configuration */
#define BOARD_CAMERA_I2C_BASEADDR             LPI2C1
#define BOARD_CAMERA_I2C_CLOCK_SOURCE_DIVIDER (5U)
#define BOARD_CAMERA_I2C_CLOCK_SOURCE_SELECT  (0U) /* Select USB1 PLL (480 MHz) as LPI2C's clock source */
#define BOARD_CAMERA_I2C_CLOCK_FREQ \
    (CLOCK_GetFreq(kCLOCK_Usb1PllClk) / 8 / (BOARD_CAMERA_I2C_CLOCK_SOURCE_DIVIDER + 1U))

#define BOARD_CAMERA_I2C_SCL_GPIO GPIO1
#define BOARD_CAMERA_I2C_SCL_PIN  16
#define BOARD_CAMERA_I2C_SDA_GPIO GPIO1
#define BOARD_CAMERA_I2C_SDA_PIN  17
#define BOARD_CAMERA_PWDN_GPIO    GPIO1
#define BOARD_CAMERA_PWDN_PIN     18

/* @Brief Board touch panel configuration */
#define BOARD_TOUCH_I2C_BASEADDR LPI2C1
#define BOARD_TOUCH_RST_GPIO     GPIO1
#define BOARD_TOUCH_RST_PIN      2
#define BOARD_TOUCH_INT_GPIO     GPIO1
#define BOARD_TOUCH_INT_PIN      11

/* @Brief Board Bluetooth HCI UART configuration */
#define BOARD_BT_UART_BASEADDR    LPUART3
#define BOARD_BT_UART_CLK_FREQ    BOARD_DebugConsoleSrcFreq()
#define BOARD_BT_UART_IRQ         LPUART3_IRQn
#define BOARD_BT_UART_IRQ_HANDLER LPUART3_IRQHandler

/*! @brief board has sdcard */
#define BOARD_HAS_SDCARD (1U)

/* In order for the NFC to be used over the ARDUINO Header
 * the SPI lines need to be enabled by soldering 0Ohm resitors over SPI lines.
 * RT1060 EVK-A R281, R279, R278, R280
 * RT1060 EVK-B
 */
#ifndef BOARD_NFC_ARDUINO_HEADER
#define BOARD_NFC_ARDUINO_HEADER (0)
#endif /* BOARD_NFC_ARDUINO_HEADER */

#define GPIO_PORT_A 1 /* GPIO1 */
#define GPIO_PORT_B 2 /* GPIO2 */
#define GPIO_PORT_C 3 /* GPIO3 */
#define GPIO_PORT_D 4 /* GPIO4 */
#define GPIO_PORT_E 5 /* GPIO5 */

#if BOARD_NFC_ARDUINO_HEADER

#define BOARD_NFC_RESET ((GPIO_PORT_A << 8) | 24) /**< RC663 nPDOWN,  GPIO1 b24, J22 P4  */
#define BOARD_NFC_IRQ   ((GPIO_PORT_A << 8) | 03) /**< RC663 IRQ,     GPIO1 b03, J24 P1 */
#define BOARD_NFC_IF0   ((GPIO_PORT_A << 8) | 20) /**< IFSEL0, GPIO1 P20, not used on CLRC663ARD  */
#define BOARD_NFC_IF1   ((GPIO_PORT_A << 8) | 21) /**< IFSEL1, GPIO1 P21, not used on CLRC663ARD  */

#define BOARD_NFC_IRQn                 GPIO1_Combined_0_15_IRQn
#define BOARD_NFC_INT_PRIORITY         8
#define BOARD_NFC_IRQHandler           GPIO1_Combined_0_15_IRQHandler
#define BOARD_NFC_PIN_IRQ_TRIGGER_TYPE PH_DRIVER_INTERRUPT_FALLINGEDGE

#define BOARD_NFC_SPI               LPSPI1
#define BOARD_NFC_IMX_SPI_DATA_RATE 5000000U
#define BOARD_NFC_IMX_SPI_CLK_SRC   LPSPI_MASTER_CLOCK_FREQ
#define BOARD_NFC_IMX_SPI_IRQ       LPSPI1_IRQn
#define BOARD_NFC_PIN_SSEL          ((GPIO_PORT_C << 8) | 13) /* Chip select pin 13 gpio3. This is the same as SPI1 PCS */
#else
#define BOARD_NFC_RESET ((GPIO_PORT_A << 8) | 24) /**< RC663 nPDOWN,  GPIO1 b24, J35 P13   */
#define BOARD_NFC_IRQ   ((GPIO_PORT_A << 8) | 25) /**< RC663 IRQ,     GPIO1 b22, J35 P11 */
#define BOARD_NFC_IF0   ((GPIO_PORT_A << 8) | 20) /**< IFSEL0, GPIO1 P20, not used on CLRC663ARD  */
#define BOARD_NFC_IF1   ((GPIO_PORT_A << 8) | 21) /**< IFSEL1, GPIO1 P21, not used on CLRC663ARD  */

#define BOARD_NFC_IRQn                 GPIO1_Combined_16_31_IRQn
#define BOARD_NFC_INT_PRIORITY         8
#define BOARD_NFC_IRQHandler           GPIO1_Combined_16_31_IRQHandler
#define BOARD_NFC_PIN_IRQ_TRIGGER_TYPE PH_DRIVER_INTERRUPT_FALLINGEDGE

#define BOARD_NFC_SPI               LPSPI3
#define BOARD_NFC_IMX_SPI_DATA_RATE 5000000U
#define BOARD_NFC_IMX_SPI_CLK_SRC   LPSPI_MASTER_CLOCK_FREQ
#define BOARD_NFC_IMX_SPI_IRQ       LPSPI3_IRQn
#define BOARD_NFC_PIN_SSEL          ((GPIO_PORT_A << 8) | 28) /* Chip select pin 28 gpio1. This is the same as SPI3 PCS */

#endif /* BOARD_NFC_ARDUINO_HEADER */

#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

/*******************************************************************************
 * API
 ******************************************************************************/
uint32_t BOARD_DebugConsoleSrcFreq(void);

void BOARD_InitDebugConsole(void);

void BOARD_ConfigMPU(void);
#if defined(SDK_I2C_BASED_COMPONENT_USED) && SDK_I2C_BASED_COMPONENT_USED
void BOARD_LPI2C_Init(LPI2C_Type *base, uint32_t clkSrc_Hz);
status_t BOARD_LPI2C_Send(LPI2C_Type *base,
                          uint8_t deviceAddress,
                          uint32_t subAddress,
                          uint8_t subaddressSize,
                          uint8_t *txBuff,
                          uint8_t txBuffSize);
status_t BOARD_LPI2C_Receive(LPI2C_Type *base,
                             uint8_t deviceAddress,
                             uint32_t subAddress,
                             uint8_t subaddressSize,
                             uint8_t *rxBuff,
                             uint8_t rxBuffSize);
status_t BOARD_LPI2C_SendSCCB(LPI2C_Type *base,
                              uint8_t deviceAddress,
                              uint32_t subAddress,
                              uint8_t subaddressSize,
                              uint8_t *txBuff,
                              uint8_t txBuffSize);
status_t BOARD_LPI2C_ReceiveSCCB(LPI2C_Type *base,
                                 uint8_t deviceAddress,
                                 uint32_t subAddress,
                                 uint8_t subaddressSize,
                                 uint8_t *rxBuff,
                                 uint8_t rxBuffSize);
void BOARD_Accel_I2C_Init(void);
status_t BOARD_Accel_I2C_Send(uint8_t deviceAddress, uint32_t subAddress, uint8_t subaddressSize, uint32_t txBuff);
status_t BOARD_Accel_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subaddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);
void BOARD_Codec_I2C_Init(void);
status_t BOARD_Codec_I2C_Send(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, const uint8_t *txBuff, uint8_t txBuffSize);
status_t BOARD_Codec_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);
void BOARD_Camera_I2C_Init(void);
status_t BOARD_Camera_I2C_Send(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, const uint8_t *txBuff, uint8_t txBuffSize);
status_t BOARD_Camera_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);

status_t BOARD_Camera_I2C_SendSCCB(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, const uint8_t *txBuff, uint8_t txBuffSize);
status_t BOARD_Camera_I2C_ReceiveSCCB(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);
status_t BOARD_Touch_I2C_Send(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, const uint8_t *txBuff, uint8_t txBuffSize);
status_t BOARD_Touch_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);
#endif /* SDK_I2C_BASED_COMPONENT_USED */

void BOARD_SD_Pin_Config(uint32_t speed, uint32_t strength);
void BOARD_MMC_Pin_Config(uint32_t speed, uint32_t strength);

#if defined(__cplusplus)
}
#endif /* __cplusplus */

#endif /* _BOARD_H_ */

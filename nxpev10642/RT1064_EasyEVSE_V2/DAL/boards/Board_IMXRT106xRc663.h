#ifndef DAL_BOARDS_BOARD_IMXRT1060RC663_H_
#define DAL_BOARDS_BOARD_IMXRT1060RC663_H_

#include "board.h"

#define GPIO_PORT_A         1    /* GPIO1 */
#define GPIO_PORT_B         2    /* GPIO2 */
#define GPIO_PORT_C         3    /* GPIO3 */
#define GPIO_PORT_D         4    /* GPIO4 */
#define GPIO_PORT_E         5    /* GPIO5 */

/******************************************************************
 * LPSPI clock configuration
 ******************************************************************/

/* Select USB1 PLL PFD0 (720 MHz) as lpspi clock source */
#define LPSPI_CLOCK_SOURCE_SELECT (1U)
/* Clock divider for master lpspi clock source */
#define LPSPI_CLOCK_SOURCE_DIVIDER (7U)

#define LPSPI_CLOCK_FREQ (CLOCK_GetFreq(kCLOCK_Usb1PllPfd0Clk) / (LPSPI_CLOCK_SOURCE_DIVIDER + 1U))

#define LPSPI_MASTER_CLOCK_FREQ LPSPI_CLOCK_FREQ


/******************************************************************
 * Board Pin/Gpio configurations
 ******************************************************************/
/* Pin configuration format : Its a 32 bit format where every byte represents a field as shown below.
 * | Byte3 | Byte2 | Byte1      | Byte0 |
 * |  --   |  --   | GPIO/PORT  | PIN   |
 * */

#define PHDRIVER_PIN_RESET BOARD_NFC_RESET
#define PHDRIVER_PIN_IRQ   BOARD_NFC_IRQ
#define PHDRIVER_PIN_IF0   BOARD_NFC_IF0
#define PHDRIVER_PIN_IF1   BOARD_NFC_IF1
/******************************************************************
 * PIN Pull-Up/Pull-Down configurations.
 ******************************************************************/
#define PHDRIVER_PIN_RESET_PULL_CFG    PH_DRIVER_PULL_DOWN
#define PHDRIVER_PIN_IRQ_PULL_CFG      PH_DRIVER_PULL_UP
#define PHDRIVER_PIN_NSS_PULL_CFG      PH_DRIVER_PULL_UP

/******************************************************************
 * IRQ PIN NVIC settings
 ******************************************************************/

#define EINT_IRQn            BOARD_NFC_IRQn
#define EINT_PRIORITY        BOARD_NFC_INT_PRIORITY
#define CLIF_IRQHandler      BOARD_NFC_IRQHandler
#define PIN_IRQ_TRIGGER_TYPE BOARD_NFC_PIN_IRQ_TRIGGER_TYPE

/*****************************************************************
 * Front End Reset logic level settings
 ****************************************************************/
#define PH_DRIVER_SET_HIGH            1          /**< Logic High. */
#define PH_DRIVER_SET_LOW             0          /**< Logic Low. */
#define RESET_POWERDOWN_LEVEL         PH_DRIVER_SET_HIGH
#define RESET_POWERUP_LEVEL           PH_DRIVER_SET_LOW

/*****************************************************************
 * SPI Configuration
 ****************************************************************/
#define PHDRIVER_IMX_SPI_POLLING          /* Enable to perform SPI transfer using polling method. */
#define PHDRIVER_IMX_SPI_MASTER           BOARD_NFC_SPI
#define PHDRIVER_IMX_SPI_DATA_RATE        BOARD_NFC_IMX_SPI_DATA_RATE
#define PHDRIVER_IMX_SPI_CLK_SRC          BOARD_NFC_IMX_SPI_CLK_SRC
#define PHDRIVER_IMX_SPI_IRQ              BOARD_NFC_IMX_SPI_IRQ
#define LPSPI_IRQ_PRIORITY                7
#define PHDRIVER_PIN_SSEL                 BOARD_NFC_PIN_SSEL

/*****************************************************************
 * Timer Configuration
 ****************************************************************/
#define PH_DRIVER_IMX_PIT_TIMER          PIT
#define PH_DRIVER_IMX_PIT_CLK            kCLOCK_OscClk
#define PH_DRIVER_IMX_TIMER_CHANNEL      kPIT_Chnl_0    /**< PIT channel number 0 */
#define PH_DRIVER_IMX_TIMER_NVIC         PIT_IRQn
#define PH_DRIVER_IMX_TIMER_PRIORITY     8


#endif /* DAL_BOARDS_BOARD_IMXRT1060RC663_H_ */

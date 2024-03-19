################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../drivers/fsl_adc16.c \
../drivers/fsl_clock.c \
../drivers/fsl_common.c \
../drivers/fsl_gpio.c \
../drivers/fsl_irtc.c \
../drivers/fsl_lptmr.c \
../drivers/fsl_lpuart.c \
../drivers/fsl_qtmr.c \
../drivers/fsl_rnga.c \
../drivers/fsl_slcd.c \
../drivers/fsl_smc.c \
../drivers/fsl_uart.c 

C_DEPS += \
./drivers/fsl_adc16.d \
./drivers/fsl_clock.d \
./drivers/fsl_common.d \
./drivers/fsl_gpio.d \
./drivers/fsl_irtc.d \
./drivers/fsl_lptmr.d \
./drivers/fsl_lpuart.d \
./drivers/fsl_qtmr.d \
./drivers/fsl_rnga.d \
./drivers/fsl_slcd.d \
./drivers/fsl_smc.d \
./drivers/fsl_uart.d 

OBJS += \
./drivers/fsl_adc16.o \
./drivers/fsl_clock.o \
./drivers/fsl_common.o \
./drivers/fsl_gpio.o \
./drivers/fsl_irtc.o \
./drivers/fsl_lptmr.o \
./drivers/fsl_lpuart.o \
./drivers/fsl_qtmr.o \
./drivers/fsl_rnga.o \
./drivers/fsl_slcd.o \
./drivers/fsl_smc.o \
./drivers/fsl_uart.o 


# Each subdirectory must supply rules for building sources it contributes
drivers/%.o: ../drivers/%.c drivers/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MKM35Z512VLQ7 -DTWR_KM35Z75M -DTOWER -DSLCD_PANEL_GDH_1247WP_H -DCPU_MKM35Z512VLQ7_cm0plus -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DFSL_RTOS_BM -DSDK_OS_BAREMETAL -DSERIAL_PORT_TYPE_UART=1 -DSDK_DEBUGCONSOLE=1 -DPRINTF_FLOAT_ENABLE=1 -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/board" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/source" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/meterlib" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/fraclib" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/CMSIS" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/drivers" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/device" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/utilities" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/slcd" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/uart" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/serial_manager" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/lists" -O0 -fno-common -g3 -gdwarf-4 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m0plus -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-drivers

clean-drivers:
	-$(RM) ./drivers/fsl_adc16.d ./drivers/fsl_adc16.o ./drivers/fsl_clock.d ./drivers/fsl_clock.o ./drivers/fsl_common.d ./drivers/fsl_common.o ./drivers/fsl_gpio.d ./drivers/fsl_gpio.o ./drivers/fsl_irtc.d ./drivers/fsl_irtc.o ./drivers/fsl_lptmr.d ./drivers/fsl_lptmr.o ./drivers/fsl_lpuart.d ./drivers/fsl_lpuart.o ./drivers/fsl_qtmr.d ./drivers/fsl_qtmr.o ./drivers/fsl_rnga.d ./drivers/fsl_rnga.o ./drivers/fsl_slcd.d ./drivers/fsl_slcd.o ./drivers/fsl_smc.d ./drivers/fsl_smc.o ./drivers/fsl_uart.d ./drivers/fsl_uart.o

.PHONY: clean-drivers


################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../component/serial_manager/serial_manager.c \
../component/serial_manager/serial_port_uart.c 

C_DEPS += \
./component/serial_manager/serial_manager.d \
./component/serial_manager/serial_port_uart.d 

OBJS += \
./component/serial_manager/serial_manager.o \
./component/serial_manager/serial_port_uart.o 


# Each subdirectory must supply rules for building sources it contributes
component/serial_manager/%.o: ../component/serial_manager/%.c component/serial_manager/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MKM35Z512VLQ7 -DTWR_KM35Z75M -DTOWER -DSLCD_PANEL_GDH_1247WP_H -DCPU_MKM35Z512VLQ7_cm0plus -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DFSL_RTOS_BM -DSDK_OS_BAREMETAL -DSERIAL_PORT_TYPE_UART=1 -DSDK_DEBUGCONSOLE=1 -DPRINTF_FLOAT_ENABLE=1 -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/board" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/source" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/meterlib" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/fraclib" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/CMSIS" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/drivers" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/device" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/utilities" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/slcd" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/component/uart" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/component/serial_manager" -I"/home/py/wrk/iotc/iotc-evse-example/nxpev1060/TWRKM3575_EVSE/component/lists" -O0 -fno-common -g3 -gdwarf-4 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m0plus -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-component-2f-serial_manager

clean-component-2f-serial_manager:
	-$(RM) ./component/serial_manager/serial_manager.d ./component/serial_manager/serial_manager.o ./component/serial_manager/serial_port_uart.d ./component/serial_manager/serial_port_uart.o

.PHONY: clean-component-2f-serial_manager


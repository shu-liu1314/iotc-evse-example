################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../board/board.c \
../board/clock_config.c \
../board/peripherals.c \
../board/pin_mux.c 

C_DEPS += \
./board/board.d \
./board/clock_config.d \
./board/peripherals.d \
./board/pin_mux.d 

OBJS += \
./board/board.o \
./board/clock_config.o \
./board/peripherals.o \
./board/pin_mux.o 


# Each subdirectory must supply rules for building sources it contributes
board/%.o: ../board/%.c board/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MKM35Z512VLQ7 -DTWR_KM35Z75M -DTOWER -DSLCD_PANEL_GDH_1247WP_H -DCPU_MKM35Z512VLQ7_cm0plus -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DFSL_RTOS_BM -DSDK_OS_BAREMETAL -DSERIAL_PORT_TYPE_UART=1 -DSDK_DEBUGCONSOLE=1 -DPRINTF_FLOAT_ENABLE=1 -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/board" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/source" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/meterlib" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/fraclib" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/CMSIS" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/drivers" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/device" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/utilities" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/slcd" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/uart" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/serial_manager" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/lists" -O0 -fno-common -g3 -gdwarf-4 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m0plus -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-board

clean-board:
	-$(RM) ./board/board.d ./board/board.o ./board/clock_config.d ./board/clock_config.o ./board/peripherals.d ./board/peripherals.o ./board/pin_mux.d ./board/pin_mux.o

.PHONY: clean-board


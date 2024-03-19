################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../source/PWR_Main.c \
../source/mtb.c \
../source/semihost_hardfault.c 

C_DEPS += \
./source/PWR_Main.d \
./source/mtb.d \
./source/semihost_hardfault.d 

OBJS += \
./source/PWR_Main.o \
./source/mtb.o \
./source/semihost_hardfault.o 


# Each subdirectory must supply rules for building sources it contributes
source/%.o: ../source/%.c source/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MKM35Z512VLQ7 -DTWR_KM35Z75M -DTOWER -DSLCD_PANEL_GDH_1247WP_H -DCPU_MKM35Z512VLQ7_cm0plus -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DFSL_RTOS_BM -DSDK_OS_BAREMETAL -DSERIAL_PORT_TYPE_UART=1 -DSDK_DEBUGCONSOLE=1 -DPRINTF_FLOAT_ENABLE=1 -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/board" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/source" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/meterlib" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/fraclib" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/CMSIS" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/drivers" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/device" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/utilities" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/slcd" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/uart" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/serial_manager" -I"/tmp/shu/iotc-evse-example/nxpev10642/TWRKM3575_EVSE/component/lists" -O0 -fno-common -g3 -gdwarf-4 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m0plus -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-source

clean-source:
	-$(RM) ./source/PWR_Main.d ./source/PWR_Main.o ./source/mtb.d ./source/mtb.o ./source/semihost_hardfault.d ./source/semihost_hardfault.o

.PHONY: clean-source


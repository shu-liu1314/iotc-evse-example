################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection.c \
../azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors_info.c \
../azure_iot/azure_iot_security_module/iot-security-module-core/src/components_factory.c \
../azure_iot/azure_iot_security_module/iot-security-module-core/src/components_manager.c \
../azure_iot/azure_iot_security_module/iot-security-module-core/src/core.c \
../azure_iot/azure_iot_security_module/iot-security-module-core/src/logger.c \
../azure_iot/azure_iot_security_module/iot-security-module-core/src/object_pool_static.c 

C_DEPS += \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection.d \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors_info.d \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_factory.d \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_manager.d \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/core.d \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/logger.d \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/object_pool_static.d 

OBJS += \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection.o \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors_info.o \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_factory.o \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_manager.o \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/core.o \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/logger.o \
./azure_iot/azure_iot_security_module/iot-security-module-core/src/object_pool_static.o 


# Each subdirectory must supply rules for building sources it contributes
azure_iot/azure_iot_security_module/iot-security-module-core/src/%.o: ../azure_iot/azure_iot_security_module/iot-security-module-core/src/%.c azure_iot/azure_iot_security_module/iot-security-module-core/src/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -DCPU_MIMXRT1062DVL6A -DCPU_MIMXRT1062DVL6A_cm7 -DSDK_DEBUGCONSOLE=0 -DXIP_EXTERNAL_FLASH=1 -DXIP_BOOT_HEADER_ENABLE=1 -DFSL_FEATURE_PHYKSZ8081_USE_RMII50M_MODE -DSDK_DEBUGCONSOLE_UART -DSCANF_FLOAT_ENABLE=1 -DPRINTF_ADVANCED_ENABLE=1 -DSCANF_ADVANCED_ENABLE=0 -DSERIAL_PORT_TYPE_UART=1 -DDATA_SECTION_IS_CACHEABLE=1 -DAZ_NO_PRECONDITION_CHECKING -DNX_INCLUDE_USER_DEFINE_FILE -DFX_INCLUDE_USER_DEFINE_FILE -DTX_INCLUDE_USER_DEFINE_FILE -DFSL_RTOS_THREADX -DMCUXPRESSO_SDK -DCR_INTEGER_PRINTF -D__MCUXPRESSO -D__USE_CMSIS -DNDEBUG -D__NEWLIB__ -DCLEV663_ENABLE=1 -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/mdio" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/phy" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/drivers" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/device" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/utilities" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/component/uart" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/component/serial_manager" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/component/lists" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/xip" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/auto_ip" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/cloud" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/dhcp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/dns" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/ftp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/http" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/lwm2m" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/mdns" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/mqtt" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/nat" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/pop3" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/ppp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/pppoe" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/ptp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/smtp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/snmp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/sntp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/telnet" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/tftp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/web" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/crypto_libraries/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/nx_secure/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/nx_secure/ports" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/filex/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/filex/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/threadx/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/threadx/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/CMSIS" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/board" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/guix/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/guix/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/mdio" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/phy" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/drivers" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/device" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/utilities" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/component/uart" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/component/serial_manager" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/component/lists" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/xip" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/auto_ip" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/cloud" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/dhcp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/dns" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/ftp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/http" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/lwm2m" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/mdns" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/mqtt" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/nat" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/pop3" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/ppp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/pppoe" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/ptp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/smtp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/snmp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/sntp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/telnet" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/tftp" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/addons/web" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/crypto_libraries/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/nx_secure/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/nx_secure/ports" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/netxduo/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/filex/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/filex/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/threadx/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/threadx/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/CMSIS" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/board" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/guix/common/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/guix/ports/cortex_m7/gnu/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/source" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot/azure-sdk-for-c/sdk/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot/azure_iot_security_module" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot/azure_iot_security_module/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot/azure_iot_security_module/inc/configs/RTOS_BASE" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot/azure_iot_security_module/iot-security-module-core/inc" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot/azure_iot_security_module/iot-security-module-core/deps/flatcc/src/runtime" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure_iot/azure_iot_security_module/iot-security-module-core/deps/flatcc/include" -I"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/config" -O1 -fno-common -g -gdwarf-4 -c -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m7 -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -D__NEWLIB__ -fstack-usage -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-azure_iot-2f-azure_iot_security_module-2f-iot-2d-security-2d-module-2d-core-2f-src

clean-azure_iot-2f-azure_iot_security_module-2f-iot-2d-security-2d-module-2d-core-2f-src:
	-$(RM) ./azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection.d ./azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection.o ./azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors_info.d ./azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors_info.o ./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_factory.d ./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_factory.o ./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_manager.d ./azure_iot/azure_iot_security_module/iot-security-module-core/src/components_manager.o ./azure_iot/azure_iot_security_module/iot-security-module-core/src/core.d ./azure_iot/azure_iot_security_module/iot-security-module-core/src/core.o ./azure_iot/azure_iot_security_module/iot-security-module-core/src/logger.d ./azure_iot/azure_iot_security_module/iot-security-module-core/src/logger.o ./azure_iot/azure_iot_security_module/iot-security-module-core/src/object_pool_static.d ./azure_iot/azure_iot_security_module/iot-security-module-core/src/object_pool_static.o

.PHONY: clean-azure_iot-2f-azure_iot_security_module-2f-iot-2d-security-2d-module-2d-core-2f-src


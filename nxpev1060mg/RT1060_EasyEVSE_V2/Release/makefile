################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include xip/subdir.mk
-include utilities/subdir.mk
-include startup/subdir.mk
-include source/subdir.mk
-include ports/subdir.mk
-include phy/subdir.mk
-include mdio/subdir.mk
-include drivers/subdir.mk
-include device/subdir.mk
-include component/uart/subdir.mk
-include component/serial_manager/subdir.mk
-include component/lists/subdir.mk
-include board/subdir.mk
-include azure_iot/azure_iot_security_module/src/utils/subdir.mk
-include azure_iot/azure_iot_security_module/src/model/objects/subdir.mk
-include azure_iot/azure_iot_security_module/src/collectors/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/src/utils/collection/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/src/utils/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/extensions/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/src/model/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/src/subdir.mk
-include azure_iot/azure_iot_security_module/iot-security-module-core/deps/flatcc/src/runtime/subdir.mk
-include azure_iot/azure_iot_security_module/subdir.mk
-include azure_iot/azure-sdk-for-c/sdk/src/azure/platform/subdir.mk
-include azure_iot/azure-sdk-for-c/sdk/src/azure/iot/subdir.mk
-include azure_iot/azure-sdk-for-c/sdk/src/azure/core/subdir.mk
-include azure_iot/subdir.mk
-include azure-rtos/threadx/ports/cortex_m7/gnu/src/subdir.mk
-include azure-rtos/threadx/ports/common/subdir.mk
-include azure-rtos/netxduo/addons/web/subdir.mk
-include azure-rtos/netxduo/addons/tftp/subdir.mk
-include azure-rtos/netxduo/addons/telnet/subdir.mk
-include azure-rtos/netxduo/addons/sntp/subdir.mk
-include azure-rtos/netxduo/addons/snmp/subdir.mk
-include azure-rtos/netxduo/addons/smtp/subdir.mk
-include azure-rtos/netxduo/addons/ptp/subdir.mk
-include azure-rtos/netxduo/addons/pppoe/subdir.mk
-include azure-rtos/netxduo/addons/ppp/subdir.mk
-include azure-rtos/netxduo/addons/pop3/subdir.mk
-include azure-rtos/netxduo/addons/nat/subdir.mk
-include azure-rtos/netxduo/addons/mqtt/subdir.mk
-include azure-rtos/netxduo/addons/mdns/subdir.mk
-include azure-rtos/netxduo/addons/lwm2m/subdir.mk
-include azure-rtos/netxduo/addons/http/subdir.mk
-include azure-rtos/netxduo/addons/ftp/subdir.mk
-include azure-rtos/netxduo/addons/dns/subdir.mk
-include azure-rtos/netxduo/addons/dhcp/subdir.mk
-include azure-rtos/netxduo/addons/cloud/subdir.mk
-include azure-rtos/netxduo/addons/auto_ip/subdir.mk
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

OPTIONAL_TOOL_DEPS := \
$(wildcard ../makefile.defs) \
$(wildcard ../makefile.init) \
$(wildcard ../makefile.targets) \


BUILD_ARTIFACT_NAME := RT1060_EasyEVSE_V2
BUILD_ARTIFACT_EXTENSION := axf
BUILD_ARTIFACT_PREFIX :=
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all:
	+@$(MAKE) --no-print-directory main-build && $(MAKE) --no-print-directory post-build

# Main-build Target
main-build: RT1060_EasyEVSE_V2.axf

# Tool invocations
RT1060_EasyEVSE_V2.axf: $(OBJS) $(USER_OBJS) makefile $(OPTIONAL_TOOL_DEPS)
	@echo 'Building target: $@'
	@echo 'Invoking: MCU Linker'
	arm-none-eabi-gcc -nostdlib -L"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/binary/netxduo/cortex_m7/mcux" -L"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/binary/filex/cortex_m7/mcux" -L"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/binary/threadx/cortex_m7/mcux" -L"/tmp/dmz2/iotc-evse-example/nxpev1060mg/RT1060_EasyEVSE_V2/azure-rtos/binary/guix/cortex_m7/mcux" -Xlinker -Map="RT1060_EasyEVSE_V2.map" -Xlinker --gc-sections -Xlinker -print-memory-usage -Xlinker --sort-section=alignment -Xlinker --cref -mcpu=cortex-m7 -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -T RT1060_EasyEVSE_V2_Release.ld -o "RT1060_EasyEVSE_V2.axf" $(OBJS) $(USER_OBJS) $(LIBS) -lnetxduo -lfilex -lthreadx -lguix
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) RT1060_EasyEVSE_V2.axf
	-@echo ' '

post-build:
	-@echo 'Performing post-build steps'
	-arm-none-eabi-size "RT1060_EasyEVSE_V2.axf"; # arm-none-eabi-objcopy -v -O binary "RT1060_EasyEVSE_V2.axf" "RT1060_EasyEVSE_V2.bin" ; # checksum -p MIMXRT1062xxxxA -d "RT1060_EasyEVSE_V2.bin";
	-@echo ' '

.PHONY: all clean dependents main-build post-build

-include ../makefile.targets

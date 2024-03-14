################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include utilities/subdir.mk
-include startup/subdir.mk
-include source/subdir.mk
-include slcd/subdir.mk
-include drivers/subdir.mk
-include device/subdir.mk
-include component/uart/subdir.mk
-include component/serial_manager/subdir.mk
-include component/lists/subdir.mk
-include board/subdir.mk
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


BUILD_ARTIFACT_NAME := TWRKM3575_EVSE
BUILD_ARTIFACT_EXTENSION := axf
BUILD_ARTIFACT_PREFIX :=
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all:
	+@$(MAKE) --no-print-directory main-build && $(MAKE) --no-print-directory post-build

# Main-build Target
main-build: TWRKM3575_EVSE.axf

# Tool invocations
TWRKM3575_EVSE.axf: $(OBJS) $(USER_OBJS) makefile $(OPTIONAL_TOOL_DEPS)
	@echo 'Building target: $@'
	@echo 'Invoking: MCU Linker'
	arm-none-eabi-gcc -nostdlib -L"/tmp/shu/nxpev10642/TWRKM3575_EVSE/meterlib" -L"/tmp/shu/nxpev10642/TWRKM3575_EVSE/fraclib" -Xlinker -Map="TWRKM3575_EVSE.map" -Xlinker --gc-sections -Xlinker -print-memory-usage -Xlinker --sort-section=alignment -Xlinker --cref -mcpu=cortex-m0plus -mthumb -T TWRKM3575_EVSE_Debug.ld -o "TWRKM3575_EVSE.axf" $(OBJS) $(USER_OBJS) $(LIBS) -lmeter_cm0p_mmau_gcc -lfrac_cm0p_mmau_gcc
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) TWRKM3575_EVSE.axf
	-@echo ' '

post-build:
	-@echo 'Performing post-build steps'
	-arm-none-eabi-size "TWRKM3575_EVSE.axf"; # arm-none-eabi-objcopy -v -O binary "TWRKM3575_EVSE.axf" "TWRKM3575_EVSE.bin" ; # checksum -p MKM35Z512xxx7 -d "TWRKM3575_EVSE.bin";
	-@echo ' '

.PHONY: all clean dependents main-build post-build

-include ../makefile.targets

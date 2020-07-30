# SPDX-License-Identifier: GPL-3.0-or-later

DC ?= gdc-10.1.0
BUILD_DIR ?= build

DFLAGS ?= \
	-msse4.2


TARGET := tunneled
SRCS := \
	src/tunneled/main.d \
	src/tunneled/vpn.d \
	src/tunneled/util.d \
	src/tunneled/capability.d \
	src/tunneled/cgroup.d \
	src/tunneled/net.d
DFLAGS := $(DFLAGS) -I src

SRCS := $(SRCS) \
	vendor/asdf/source/asdf/asdf.d \
	vendor/asdf/source/asdf/jsonbuffer.d \
	vendor/asdf/source/asdf/jsonparser.d \
	vendor/asdf/source/asdf/outputarray.d \
	vendor/asdf/source/asdf/package.d \
	vendor/asdf/source/asdf/serialization.d \
	vendor/asdf/source/asdf/transform.d \
	vendor/asdf/source/asdf/utility.d
DFLAGS := $(DFLAGS) -I vendor/asdf/source

LIBS := \
	rt \
	cap


MKDIR ?= mkdir -p
RMDIR ?= $(RM) -r


OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
OBJS := $(OBJS:.d.o=.o)
DEPS := $(OBJS:.o=.deps)
LDFLAGS := $(LDFLAGS) $(foreach lib,$(LIBS),-l$(lib))


DFLAGS := $(DFLAGS) \
	-MMD -MP
LDFLAGS := $(LDFLAGS) \
	-static-libphobos \
	-static-libgcc

$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(DC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.d
	$(MKDIR) $(dir $@)
	$(DC) $(DFLAGS) -MF $(basename $@).deps -c $< -o $@

.PHONY: clean

setcap: $(BUILD_DIR)/$(TARGET)
	setcap cap_dac_override,cap_net_admin+p $(BUILD_DIR)/$(TARGET)

clean:
	$(RMDIR) $(BUILD_DIR)

-include $(DEPS)

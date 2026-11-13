CC := gcc

TASIGN_TOOL ?= $(shell which tasign-tool 2>/dev/null || echo "~/.cargo/bin/tasign-tool")
SIGN_ALGORITHM ?= sm2-sm3
# 签名证书路径
#   未设置 → 使用 tasign 内置 TEST 证书（开发调试用）；
#   已设置 → 使用指定路径的生产证书，验签时验证证书链到根。
KYCA_LEAF_CERT ?=
KYCA_INTERMEDIATE_CERT ?=
KYCA_LEAF_KEY ?=
KYCA_LEAF_KEY_PASS ?=
# CA 根证书路径（生产模式验签时使用）
# 默认使用项目内置证书，可通过环境变量覆盖
VERIFY_CA_CERT ?= ../certs/kylin-xtee-ca-sign-root.pem
# 中间证书数量（生产模式默认为 0，可覆盖；TEST 模式固定为 1）
KYCA_INTERMEDIATE_COUNT ?= 0
SIGN_OUTPUT_DIR ?= signed

DEBUG ?= 0

# Android cross-compilation configuration (ANDROID_API_LEVEL, ANDROID_TARGET inherited from parent Makefile)
ANDROID_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(ANDROID_TARGET)$(ANDROID_API_LEVEL)-clang
ANDROID_OBJCOPY := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy
ANDROID_LIB_DIR := $(CURDIR)/../target/$(ANDROID_TARGET)/release
ANDROID_SIGN_OUTPUT_DIR := signed-android

CC_TEEC_TARGET := cc-teec
KYBOX_TEST_TARGET := kybox-test
KYDE_TEST_TARGET := kyde-test
TARGETS := $(CC_TEEC_TARGET) $(KYBOX_TEST_TARGET) $(KYDE_TEST_TARGET)

TEE_CLIENT_SRC := tee_client.c
CC_TEEC_SRCS := cc-teec.c $(TEE_CLIENT_SRC)
KYBOX_TEST_SRCS := kybox-test.c $(TEE_CLIENT_SRC)
KYDE_TEST_SRCS := kyde-test.c $(TEE_CLIENT_SRC)
ALL_SRCS := $(CC_TEEC_SRCS) $(KYBOX_TEST_SRCS) $(KYDE_TEST_SRCS)

INC_DIR := include

BASE_CFLAGS := \
	-I$(INC_DIR) \
	-D_GNU_SOURCE \
	-DBINARY_PREFIX=\"TEEC\" \
	-std=gnu11

# 安全编译选项
SECURITY_CFLAGS := \
	-Wall \
	-Werror \
	-Wextra \
	-Wformat-security \
	-Wstrict-prototypes \
	-Wshadow \
	-Wunused \
	-Wcast-align \
	-Wpointer-arith
	#-Wmissing-prototypes
	#-Wmissing-declarations

# 安全链接选项
SECURITY_LDFLAGS := \
	-Wl,--as-needed \
	-Wl,-z,relro \
	-Wl,-z,now \
	-Wl,-z,noexecstack \
	-Wl,--no-undefined \
	-Wl,--fatal-warnings

# 位置无关代码
PIE_CFLAGS := -fPIE -fpie
PIE_LDFLAGS := -pie

# 栈保护
STACK_PROTECTOR := -fstack-protector-strong

# 优化选项
ifeq ($(BUILD_MODE), release)
	OPTIMIZE_CFLAGS := -O2
	OPTIMIZE_LDFLAGS := -s
else
	OPTIMIZE_CFLAGS := -O0 -ggdb3
	OPTIMIZE_LDFLAGS := -g
endif

# 调试选项
ifeq ($(DEBUG), 1)
	DEBUG_CFLAGS := -g3
	DEBUG_LDFLAGS := -g
else
	DEBUG_CFLAGS :=
	DEBUG_LDFLAGS :=
endif

CFLAGS := \
	$(BASE_CFLAGS) \
	$(SECURITY_CFLAGS) \
	$(PIE_CFLAGS) \
	$(STACK_PROTECTOR) \
	$(OPTIMIZE_CFLAGS) \
	$(DEBUG_CFLAGS)

LDFLAGS := \
	$(PIE_LDFLAGS) \
	$(SECURITY_LDFLAGS) \
	$(OPTIMIZE_LDFLAGS) \
	$(DEBUG_LDFLAGS)

LIBS := -l$(RUST_LIB_NAME)

.PHONY: all
all: check-tasign $(TARGETS) sign-all

# 检查 tasign-tool 是否存在
.PHONY: check-tasign
check-tasign:
	@if [ ! -x "$(TASIGN_TOOL)" ]; then \
		echo "Error: tasign-tool not found at $(TASIGN_TOOL)"; \
		echo "Please install tasign-tool:"; \
		echo "  cargo install tasign --force"; \
		echo "Or set TASIGN_TOOL environment variable to the correct path"; \
		exit 1; \
	fi
	@echo "Using tasign-tool: $(TASIGN_TOOL)"

# 编译所有目标
define BUILD_TARGET
$(1): $(2) $$(RUST_TARGET_BUILD_DIR)/$$(RUST_LIB_FILE)
	@if [ ! -f "$$(RUST_TARGET_BUILD_DIR)/$$(RUST_LIB_FILE)" ]; then \
		echo "Error: Rust library $$(RUST_LIB_FILE) not found in $$(RUST_TARGET_BUILD_DIR)"; \
		echo "Please build the Rust library first: cd .. && cargo build --release"; \
		exit 1; \
	fi; \
	echo "Using Rust library: $$(RUST_TARGET_BUILD_DIR)/$$(RUST_LIB_FILE)"; \
	$$(CC) $$(CFLAGS) $$(LDFLAGS) -o $$@ $$^ -L$$(RUST_TARGET_BUILD_DIR) $$(LIBS)
endef

$(eval $(call BUILD_TARGET,$(CC_TEEC_TARGET),$(CC_TEEC_SRCS)))
$(eval $(call BUILD_TARGET,$(KYBOX_TEST_TARGET),$(KYBOX_TEST_SRCS)))
$(eval $(call BUILD_TARGET,$(KYDE_TEST_TARGET),$(KYDE_TEST_SRCS)))

# 对所有目标进行签名
# 与 x-biometric/Makefile 保持一致的判断逻辑：
#   KYCA_LEAF_CERT 为空 → 内置 TEST 证书；非空 → 生产证书
.PHONY: sign-all
sign-all: $(addprefix sign-,$(TARGETS))

# 签名单个目标
.PHONY: sign-%
sign-%: %
ifeq ($(KYCA_LEAF_CERT),)
	@echo "Signing $< (TEST certs)..."
	@# 如果已存在 .ta_signature section，先清理
	@if objdump -h $< | grep -q ".ta_signature"; then \
		echo "Removing existing .ta_signature section..."; \
		objcopy --remove-section .ta_signature $< $<.tmp && mv $<.tmp $<; \
	fi
	@mkdir -p $(SIGN_OUTPUT_DIR)/$<
	@$(TASIGN_TOOL) sign \
		--elf $< \
		--out-dir $(SIGN_OUTPUT_DIR)/$< \
		--leaf-cert TEST \
		--intermediate-cert TEST \
		--intermediate-count 1 \
		--algorithm $(SIGN_ALGORITHM) \
		--leaf-key TEST \
		--leaf-key-pass TEST
	@$(TASIGN_TOOL) write-elf \
		--input-elf $< \
		--signature-bin $(SIGN_OUTPUT_DIR)/$</signature.bin \
		--output-elf $< \
		--objcopy objcopy
	@$(TASIGN_TOOL) verify-elf --elf $< --ca-cert TEST && \
		echo "✓ Successfully signed and verified: $<" || \
		(echo "✗ Signature verification failed for $<"; exit 1)
else
	@echo "Signing $< (production certs)..."
	@# 如果已存在 .ta_signature section，先清理
	@if objdump -h $< | grep -q ".ta_signature"; then \
		echo "Removing existing .ta_signature section..."; \
		objcopy --remove-section .ta_signature $< $<.tmp && mv $<.tmp $<; \
	fi
	@mkdir -p $(SIGN_OUTPUT_DIR)/$<
	@$(TASIGN_TOOL) sign \
		--elf $< \
		--out-dir $(SIGN_OUTPUT_DIR)/$< \
		--leaf-cert $(KYCA_LEAF_CERT) \
		--intermediate-count $(KYCA_INTERMEDIATE_COUNT) \
		--algorithm $(SIGN_ALGORITHM) \
		--leaf-key $(KYCA_LEAF_KEY) \
		--leaf-key-pass $(KYCA_LEAF_KEY_PASS) \
		$(if $(KYCA_INTERMEDIATE_CERT),--intermediate-cert $(KYCA_INTERMEDIATE_CERT))
	@$(TASIGN_TOOL) write-elf \
		--input-elf $< \
		--signature-bin $(SIGN_OUTPUT_DIR)/$</signature.bin \
		--output-elf $< \
		--objcopy objcopy
	@$(TASIGN_TOOL) verify-elf --elf $< --ca-cert $(VERIFY_CA_CERT) && \
		echo "✓ Successfully signed and verified: $<" || \
		(echo "✗ Signature verification failed for $<"; exit 1)
endif

.PHONY: clean
clean:
	rm -rf $(TARGETS) $(SIGN_OUTPUT_DIR) $(ANDROID_SIGN_OUTPUT_DIR)

# Android cross-compilation targets
android-ndk-check:
	@if [ -z "$(ANDROID_NDK_HOME)" ]; then \
		echo "Error: ANDROID_NDK_HOME is not set. Please export ANDROID_NDK_HOME=/path/to/android-ndk-r29"; \
		exit 1; \
	fi

define ANDROID_BUILD_TARGET
android-$(1): android-ndk-check
	@if [ ! -f "$$(ANDROID_CC)" ]; then \
		echo "Error: NDK compiler not found at $$(ANDROID_CC)"; \
		echo "Set ANDROID_NDK_HOME to your NDK installation path"; \
		exit 1; \
	fi
	@if [ ! -f "$$(ANDROID_LIB_DIR)/$$(RUST_LIB_FILE)" ]; then \
		echo "Error: $$(RUST_LIB_FILE) not found at $$(ANDROID_LIB_DIR)"; \
		echo "Build it first: cd .. && make android"; \
		exit 1; \
	fi
	@echo "Building $(1) for Android $$(ANDROID_TARGET)..."
	$$(ANDROID_CC) $$(BASE_CFLAGS) $$(SECURITY_CFLAGS) -fstack-protector-strong -fPIE -O2 \
		-I$$(INC_DIR) -o $(1) $(2) \
		-L$$(ANDROID_LIB_DIR) -Wl,-rpath,/vendor/lib64 -l$$(RUST_LIB_NAME) -ldl
	@echo "Android build completed: $(1)"
endef

$(eval $(call ANDROID_BUILD_TARGET,$(CC_TEEC_TARGET),$(CC_TEEC_SRCS)))
$(eval $(call ANDROID_BUILD_TARGET,$(KYBOX_TEST_TARGET),$(KYBOX_TEST_SRCS)))
$(eval $(call ANDROID_BUILD_TARGET,$(KYDE_TEST_TARGET),$(KYDE_TEST_SRCS)))

android: android-$(CC_TEEC_TARGET) android-$(KYBOX_TEST_TARGET) android-$(KYDE_TEST_TARGET)

define ANDROID_SIGN_TARGET
android-sign-$(1): android-$(1)
	@echo "Signing $(1) (Android)..."
	@if $$(ANDROID_OBJCOPY) --dump-section .ta_signature=/dev/null $(1) 2>/dev/null; then \
		echo "Removing existing .ta_signature section..."; \
		$$(ANDROID_OBJCOPY) --remove-section .ta_signature $(1) $(1).tmp && mv $(1).tmp $(1); \
	fi
	@mkdir -p $$(ANDROID_SIGN_OUTPUT_DIR)/$(1)
ifeq ($(KYCA_LEAF_CERT),)
	@$$(TASIGN_TOOL) sign \
		--elf $(1) \
		--out-dir $$(ANDROID_SIGN_OUTPUT_DIR)/$(1) \
		--leaf-cert TEST \
		--intermediate-cert TEST \
		--intermediate-count 1 \
		--algorithm $$(SIGN_ALGORITHM) \
		--leaf-key TEST \
		--leaf-key-pass TEST
	@$$(TASIGN_TOOL) write-elf \
		--input-elf $(1) \
		--signature-bin $$(ANDROID_SIGN_OUTPUT_DIR)/$(1)/signature.bin \
		--output-elf $(1) \
		--objcopy $$(ANDROID_OBJCOPY)
	@$$(TASIGN_TOOL) verify-elf --elf $(1) --ca-cert TEST && \
		echo "✓ Successfully signed and verified: $(1) (Android)" || \
		(echo "✗ Signature verification failed for $(1) (Android)"; exit 1)
else
	@$$(TASIGN_TOOL) sign \
		--elf $(1) \
		--out-dir $$(ANDROID_SIGN_OUTPUT_DIR)/$(1) \
		--leaf-cert $$(KYCA_LEAF_CERT) \
		--intermediate-count $$(KYCA_INTERMEDIATE_COUNT) \
		--algorithm $$(SIGN_ALGORITHM) \
		--leaf-key $$(KYCA_LEAF_KEY) \
		--leaf-key-pass $$(KYCA_LEAF_KEY_PASS) \
		$$(if $$(KYCA_INTERMEDIATE_CERT),--intermediate-cert $$(KYCA_INTERMEDIATE_CERT))
	@$$(TASIGN_TOOL) write-elf \
		--input-elf $(1) \
		--signature-bin $$(ANDROID_SIGN_OUTPUT_DIR)/$(1)/signature.bin \
		--output-elf $(1) \
		--objcopy $$(ANDROID_OBJCOPY)
	@$$(TASIGN_TOOL) verify-elf --elf $(1) --ca-cert $$(VERIFY_CA_CERT) && \
		echo "✓ Successfully signed and verified: $(1) (Android)" || \
		(echo "✗ Signature verification failed for $(1) (Android)"; exit 1)
endif
endef

$(eval $(call ANDROID_SIGN_TARGET,$(CC_TEEC_TARGET)))
$(eval $(call ANDROID_SIGN_TARGET,$(KYBOX_TEST_TARGET)))
$(eval $(call ANDROID_SIGN_TARGET,$(KYDE_TEST_TARGET)))

android-sign: android-sign-$(CC_TEEC_TARGET) android-sign-$(KYBOX_TEST_TARGET) android-sign-$(KYDE_TEST_TARGET)

.PHONY: all check-tasign sign-all sign-% clean \
        android-ndk-check android android-sign \
        android-$(CC_TEEC_TARGET) android-$(KYBOX_TEST_TARGET) android-$(KYDE_TEST_TARGET) \
        android-sign-$(CC_TEEC_TARGET) android-sign-$(KYBOX_TEST_TARGET) android-sign-$(KYDE_TEST_TARGET)

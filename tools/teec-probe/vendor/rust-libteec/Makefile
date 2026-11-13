CARGO := cargo
export BUILD_MODE ?= release
# 透传给 cargo build 的 feature（空格分隔）：
#   make build-c-examples CARGO_FEATURES=test-root-ca
# 用于 TEST 签名的 c-example：库需以 test-root-ca 构建才能在运行时
# 验证 TEST 证书链（默认构建嵌入生产根证书，会报 chain build failed）。
export CARGO_FEATURES ?=

ROOT_DIR := $(CURDIR)
C_EXAMPLES_DIR := $(ROOT_DIR)/c-examples
EXAMPLES_DIR := $(ROOT_DIR)/examples
RUST_TARGET_DIR := $(ROOT_DIR)/target
export RUST_LIB_NAME := cc_teec
export RUST_LIB_FILE := lib$(RUST_LIB_NAME).so

# Android cross-compilation configuration
export ANDROID_API_LEVEL ?= 35
export ANDROID_TARGET := aarch64-linux-android
ANDROID_OUT_DIR := $(RUST_TARGET_DIR)/$(ANDROID_TARGET)/release

ifeq ($(BUILD_MODE), release)
	CARGO_FLAGS += --release
	BUILD_TYPE := release
	CARGO_PROFILE := --profile release
else
	BUILD_TYPE := debug
	CARGO_PROFILE :=
endif

export RUST_TARGET_BUILD_DIR := $(RUST_TARGET_DIR)/$(BUILD_TYPE)
export LD_LIBRARY_PATH=$(RUST_TARGET_BUILD_DIR):$$LD_LIBRARY_PATH

CARGO_BUILD_FLAGS := $(CARGO_FLAGS)
CARGO_TEST_FLAGS := $(CARGO_FLAGS)
CARGO_DOC_FLAGS := $(CARGO_FLAGS)

.DEFAULT_GOAL := all

.PHONY: all
all: build test

.PHONY: build
build: build-rust build-c-examples

.PHONY: build-rust
build-rust:
	@echo "Building Rust library and examples..."
	$(CARGO) build $(CARGO_BUILD_FLAGS) --lib $(if $(CARGO_FEATURES),--features $(CARGO_FEATURES))
	$(CARGO) build $(CARGO_BUILD_FLAGS) --example cc-teec $(if $(CARGO_FEATURES),--features $(CARGO_FEATURES))
	@echo "Rust build completed"

.PHONY: build-c-examples
build-c-examples:
	@echo "Building C examples..."
	$(MAKE) -C $(C_EXAMPLES_DIR)
	@echo "C examples build completed"

.PHONY: test
test:
	@echo "Running Rust tests..."
	$(CARGO) test $(CARGO_TEST_FLAGS)
	@echo "Rust tests completed"

# 仅测试基础设施：默认 cargo test 不会启用 attack-test，TLS 篡改回归用例
# 会被静默跳过。该目标保证它们进入 make check / CI 的常规校验路径。
.PHONY: test-attack
test-attack:
	@echo "Running TLS tamper regression tests (attack-test feature)..."
	$(CARGO) test $(CARGO_TEST_FLAGS) --features attack-test
	@echo "TLS tamper regression tests completed"

.PHONY: test-c-examples
test-c-examples: build-c-examples
	$(C_EXAMPLES_DIR)/cc-teec
	$(C_EXAMPLES_DIR)/kybox-test
	$(C_EXAMPLES_DIR)/kyde-test

.PHONY: doc
doc:
	@echo "Generating documentation..."
	$(CARGO) doc $(CARGO_DOC_FLAGS) --no-deps --open
	@echo "Documentation generated"

.PHONY: doc-no-open
doc-no-open:
	@echo "Generating documentation..."
	$(CARGO) doc $(CARGO_DOC_FLAGS) --no-deps
	@echo "Documentation generated"

.PHONY: fmt
fmt:
	@echo "Checking code formatting..."
	cargo fmt -- --check
	@echo "Format check completed"

.PHONY: fmt-fix
fmt-fix:
	@echo "Formatting code..."
	cargo fmt
	@echo "Code formatted"

.PHONY: clippy
clippy:
	@echo "Running Clippy..."
	$(CARGO) clippy $(CARGO_BUILD_FLAGS) -- -D warnings
	@echo "Clippy check completed"

.PHONY: audit
audit:
	@echo "Running security audit..."
	$(CARGO) audit
	@echo "Security audit completed"

.PHONY: check
check: fmt clippy audit test test-attack
	@echo "All checks passed!"

.PHONY: clean-c-examples
clean-c-examples:
	@echo "Cleaning C examples..."
	$(MAKE) -C $(C_EXAMPLES_DIR) clean
	@echo "C examples cleaned"

.PHONY: clean
clean: clean-c-examples
	@echo "Cleaning Rust build artifacts..."
	@if command -v $(CARGO) > /dev/null 2>&1; then \
		$(CARGO) clean; \
	else \
		echo "  [WARN] '$(CARGO)' not found, removing target directory directly..."; \
		rm -rf $(RUST_TARGET_DIR); \
	fi
	rm -rf coverage-report
	@echo "All cleaned"

.PHONY: release
release:
	@echo "Building release version..."
	$(MAKE) build BUILD_MODE=release
	@echo "Release build completed"

.PHONY: coverage
coverage:
# 仅在未安装时执行 cargo install，避免每次都访问 registry 重新检查/编译
	@if command -v cargo-llvm-cov >/dev/null 2>&1; then \
		echo "cargo-llvm-cov already installed"; \
	else \
		echo "cargo-llvm-cov not found, installing..."; \
		cargo install cargo-llvm-cov; \
	fi
	@echo "Running code coverage analysis..."
	mkdir -p coverage-report
	@# 1) 编译+跑测试，输出覆盖率统计表到终端
	cargo llvm-cov --workspace --no-fail-fast --features test-root-ca
	@# 2) 复用 profraw 生成 HTML 报告（不重跑测试）。
	@#    report 不接受 --workspace：裸 report 只统计根包，用 -p '*' 选中
	@#    全部 workspace 成员；HTML 生成在 --output-dir 下的 html/ 子目录。
	cargo llvm-cov report -p '*' --html --output-dir coverage-report
	@# 3) 复用 profraw 生成 Cobertura XML（不重跑测试）
	cargo llvm-cov report -p '*' --cobertura --output-path coverage-report/coverage.xml
	@echo ""
	@echo "Coverage report generated in coverage-report/"
	@echo "  HTML: coverage-report/html/index.html"
	@echo "  XML:  coverage-report/coverage.xml"

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)$(shell echo /usr/lib/$$(uname -m)-linux-gnu)/
INCLUDE_DIR ?= $(PREFIX)/usr/include/cc-teec/

.PHONY: install
install:
	@echo "Installing library and headers..."
	install -d $(LIBDIR)
	install -m 0755 $(RUST_TARGET_BUILD_DIR)/$(RUST_LIB_FILE) $(LIBDIR)
	install -d $(INCLUDE_DIR)
	install -m 0644 $(C_EXAMPLES_DIR)/include/*.h $(INCLUDE_DIR)
	@echo "Installation completed"

.PHONY: uninstall
uninstall:
	@echo "Uninstalling library..."
	# 这里可以添加卸载命令
	rm -rf $(LIBDIR)/$(RUST_LIB_FILE)
	rm -rf $(INCLUDE_DIR)
	@echo "Uninstallation completed"

build-c-examples: build-rust
test: build-rust

# Android cross-compilation targets
android-ndk-check:
	@if [ -z "$(ANDROID_NDK_HOME)" ]; then \
		echo "Error: ANDROID_NDK_HOME is not set. Please export ANDROID_NDK_HOME=/path/to/android-ndk-r29"; \
		exit 1; \
	fi

android: android-ndk-check
	@echo "Building for Android $(ANDROID_TARGET) - API $(ANDROID_API_LEVEL)..."
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) cargo ndk --platform $(ANDROID_API_LEVEL) build --target arm64-v8a --release --lib
	@echo "Android build completed: $(ANDROID_OUT_DIR)/$(RUST_LIB_FILE)"

android-c-examples: android
	@echo "Building C examples for Android..."
	$(MAKE) -C $(C_EXAMPLES_DIR) android-sign
	@echo "Android C examples build completed"

android-all: android android-c-examples

.PHONY: all build build-rust build-c-examples test test-attack\
        doc doc-no-open \
        fmt fmt-fix clippy audit check \
        clean clean-c-examples \
        release install uninstall \
        android-ndk-check android android-c-examples android-all

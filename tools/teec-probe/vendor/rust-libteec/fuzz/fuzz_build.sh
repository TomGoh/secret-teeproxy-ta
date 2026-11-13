#!/bin/bash
# WFUZZ local build: Kylin mirror may not ship rust-toolchain.toml version; use nightly.
#
# 用法: ./fuzz_build.sh
# 在 v11-2603 容器内（ubuntu 用户、已安装 WFUZZ SDK）于 fuzz/ 目录构建：
#   wfuzz build -> entrypoints-merge -> extract_entrypoints_list.py
# 构建完成后，循环读取 entrypoints_list.txt，对每个入口点在后台并行启动
# WFUZZ_TEST_ENTRYPOINT=<name> wfuzz fuzz（日志写入 wfuzz-test-<name>.log），
# 全部结束后统一等待并汇总结果。
#
# 本脚本以 wfuzz.json 所在目录（fuzz/）为测试根目录，产物收进 fuzz/ 下
# （entrypoints.json / entrypoints_list.txt / wfuzz-fuzz-targets/ /
#   wfuzz-test-*.log，均已 gitignore）。
set -euo pipefail

cd "$(dirname "$0")"

export RUSTUP_TOOLCHAIN=nightly

# 较新 nightly cargo 默认启用 build-dir layout v2，mbedtls-smx build.rs 需回退旧布局
export __CARGO_TEMPORARY_BUILD_DIR_NEW_LAYOUT_OPT_OUT=1

if ! command -v wfuzz >/dev/null 2>&1; then
  echo "error: wfuzz not found; install the WFUZZ SDK and source ~/.bashrc" >&2
  exit 1
fi

echo "==> wfuzz build (RUSTUP_TOOLCHAIN=nightly)"
wfuzz build --output-entrypoints entrypoints.json

echo "==> wfuzz entrypoints-merge"
wfuzz entrypoints-merge -w wfuzz.json -e entrypoints.json

echo "==> extract entrypoints list"
python3 extract_entrypoints_list.py wfuzz.json entrypoints_list.txt

if [ ! -s entrypoints_list.txt ]; then
  echo "error: entrypoints_list.txt is empty; no fuzz entrypoints to run" >&2
  exit 1
fi

echo ""
echo "==> launching fuzzing for all entrypoints in background"

pids=()
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  log="wfuzz-test-${ep}.log"
  echo "  [$(date +%H:%M:%S)] ${ep} -> ${log}"
  WFUZZ_TEST_ENTRYPOINT="$ep" wfuzz fuzz >"$log" 2>&1 &
  pids+=("${ep}:$!")
done < entrypoints_list.txt

echo "==> waiting for ${#pids[@]} background fuzz job(s) to finish"

failed=0
for job in "${pids[@]}"; do
  ep="${job%%:*}"
  pid="${job##*:}"
  if wait "$pid"; then
    echo "  ${ep}: OK"
  else
    echo "  ${ep}: FAILED (see wfuzz-test-${ep}.log)"
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "one or more fuzz entrypoints failed; check the failing wfuzz-test-<name>.log files" >&2
  exit 1
fi

echo ""
echo "all fuzz entrypoints finished successfully:"
tr '\n' ' ' < entrypoints_list.txt
echo ""

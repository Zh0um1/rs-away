#!/usr/bin/env bash
# doccheck —— 校验 docs/**.md 内所有 `path/to/file.go:LINE` 引用在 Go 基线仓库中真实存在且该行非空。
#
# 用法：
#   scripts/doccheck.sh [GO_BASELINE_DIR]
# 默认基线目录：/root/workspace/coding/Stowaway（plan.md §0 指定的 HEAD 7f715be）
#
# 退出码：0 = 全部引用有效；1 = 存在失效引用（打印清单）。
# 对应 plan.md §10 G8：docs: 提交必须过此检查，P0 阶段迁移为 `cargo xtask doccheck`。
set -euo pipefail

GO_DIR="${1:-/root/workspace/coding/Stowaway}"
DOCS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs"

if [ ! -d "$GO_DIR" ]; then
  echo "doccheck: 基线目录不存在: $GO_DIR" >&2
  exit 1
fi

refs="$(grep -ohE '([A-Za-z_][A-Za-z0-9_]*/){1,3}[A-Za-z_][A-Za-z0-9_]*\.go:[0-9]+(-[0-9]+)?' \
  "$DOCS_DIR"/*.md "$DOCS_DIR"/**/*.md 2>/dev/null | sort -u)"

total=0
bad=0
while IFS= read -r ref; do
  [ -z "$ref" ] && continue
  total=$((total + 1))
  file="${ref%%:*}"
  rest="${ref#*:}"
  line="${rest%%-*}"
  target="$GO_DIR/$file"
  if [ ! -f "$target" ]; then
    echo "MISSING-FILE  $ref  (无此文件: $file)"
    bad=$((bad + 1))
    continue
  fi
  content="$(sed -n "${line}p" "$target")"
  if [ -z "${content//[[:space:]]/}" ]; then
    echo "EMPTY-LINE    $ref  (该行为空或超出文件末尾)"
    bad=$((bad + 1))
  fi
done <<< "$refs"

echo "doccheck: 共检查 $total 个引用，失效 $bad 个"
[ "$bad" -eq 0 ]
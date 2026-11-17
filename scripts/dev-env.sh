#!/usr/bin/env bash
# 生成本机可写 CARGO_HOME。
#
# 为什么需要：本机 `/` 是只读挂载（`/dev/vda1 on / type ext4 (ro,...)`），
# 而 `/root/.cargo` 位于 `/` 下，cargo 解包 crate 时会写它，直接 build 会报
#   failed to open `/root/.cargo/registry/cache/.../bit-vec-0.9.1.crate`
#   Read-only file system (os error 30)
# 因此把 registry 复制到工作区内的 `.cargo-home/`（已被 .gitignore 排除），
# 并在每次构建前 `CARGO_HOME=$PWD/.cargo-home`。
#
# 该妥协只影响本机开发，CI 与普通开发机不需要。docs/plan.md §1.3 有记录。
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dst="$repo_root/.cargo-home"

if [ -d "$dst/registry" ]; then
    echo "dev-env: $dst 已存在，跳过复制"
else
    echo "dev-env: 从 $HOME/.cargo 复制 registry 到 $dst（约 800 MiB，需 1-2 分钟）"
    mkdir -p "$dst"
    cp -a "$HOME/.cargo/registry" "$dst/registry"
    if [ -f "$HOME/.cargo/config.toml" ]; then
        cp "$HOME/.cargo/config.toml" "$dst/config.toml"
    fi
fi

echo "dev-env: 已就绪。请使用下列方式构建："
echo "  export CARGO_HOME=$dst"
echo "  cargo build --workspace --all-features"
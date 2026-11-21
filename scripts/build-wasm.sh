#!/bin/sh
# Builds the Keymesh browser bridge and copies it into the Angular app.
#   apps/web/src/app/core/wasm-pkg/  JS glue + TypeScript declarations
#   apps/web/public/wasm/            keymesh_wasm_bg.wasm (served as a static asset)
# Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli matching the
# wasm-bindgen crate version pinned in crates/keymesh-wasm/Cargo.toml.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"/\1/p' "$root/crates/keymesh-wasm/Cargo.toml")
have=$(wasm-bindgen --version | awk '{print $2}')
if [ "$want" != "$have" ]; then
  echo "wasm-bindgen-cli $have does not match crate version $want" >&2
  exit 1
fi
cargo build -p keymesh-wasm --target wasm32-unknown-unknown --release ${CARGO_BUILD_JOBS:+-j "$CARGO_BUILD_JOBS"}
pkg="$root/apps/web/src/app/core/wasm-pkg"
rm -rf "$pkg" && mkdir -p "$pkg" "$root/apps/web/public/wasm"
wasm-bindgen --target web --out-dir "$pkg" \
  "$root/target/wasm32-unknown-unknown/release/keymesh_wasm.wasm"
mv "$pkg/keymesh_wasm_bg.wasm" "$root/apps/web/public/wasm/keymesh_wasm_bg.wasm"
rm -f "$pkg/keymesh_wasm_bg.wasm.d.ts"
echo "wasm bridge built: $(wc -c < "$root/apps/web/public/wasm/keymesh_wasm_bg.wasm") bytes"

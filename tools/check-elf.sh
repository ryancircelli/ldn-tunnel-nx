#!/usr/bin/env bash
# Binary gates on the built module (run by `make check` and CI after `make nsp`):
#  1. no function's stack frame over FRAME_MAX bytes. Threads run on 16-32 KiB stacks; a
#     32 KiB frame (a 16 KiB ring buffer on the stack) crashed a console, and nothing else catches it.
#  2. exefs.nsp no larger than NSP_MAX bytes.
#  3. static memory (loaded image through .bss, which holds the heap and bsd transfer memory,
#     plus main.json's main thread stack) no larger than MEM_MAX bytes: Atmosphere gives all
#     custom sysmodules ~32 MiB together.
# Frame = pre-indexed pushes (`stp x29, x30, [sp, #-N]!`) + every `sub sp, sp, #N[, lsl #12]` + the
# stack-probe loop target (`sub x9, sp, #N, lsl #12` ... `cmp sp, x9`) that LLVM emits for large frames.
# Prints the 10 largest frames.
#   tools/check-elf.sh [elf] [nsp]       env: FRAME_MAX (8192), NSP_MAX (786432), MEM_MAX (2621440), OBJDUMP
#   tools/check-elf.sh --self-test       the frame parser against llc-built probe-loop/unrolled/plain frames
set -euo pipefail
cd "$(dirname "$0")/.."
REL=crates/sys/target/aarch64-nintendo-switch-freestanding/release
FRAME_MAX=${FRAME_MAX:-8192}
NSP_MAX=${NSP_MAX:-786432}
MEM_MAX=${MEM_MAX:-2621440}

# llvm-objdump (and llc) from the toolchain's llvm-tools component (rustup component add llvm-tools)
OBJDUMP=${OBJDUMP:-$(command -v llvm-objdump || ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-objdump 2>/dev/null | head -1 || true)}
[ -x "$OBJDUMP" ] || { echo "llvm-objdump not found: rustup component add llvm-tools, or set OBJDUMP"; exit 2; }

# "<bytes>\t<function>" per function with a frame, largest first
frames() {
  "$OBJDUMP" -d -C --no-show-raw-insn "$1" | awk '
  function imm(s,   v) { v = s; sub(/^#/, "", v); return strtonum(v) }
  function flush() { if (fn != "") { f = n + (loop ? x9 - 4096 : 0); if (f > 0) printf "%d\t%s\n", f, fn } }
  /^[0-9a-f]+ <.*>:$/ { flush(); fn = substr($0, index($0, "<") + 1); sub(/>:$/, "", fn); n = 0; x9 = 0; loop = 0; next }
  {
    i = $0; sub(/^[ \t]*[0-9a-f]+:[ \t]*/, "", i); gsub(/,/, "", i); split(i, a, /[ \t]+/)
    if (a[1] ~ /^(stp|str|stur)$/ && i ~ /\[sp #-0x[0-9a-f]+\]!/) { m = i; sub(/.*\[sp #-/, "", m); sub(/\]!.*/, "", m); n += strtonum(m) }
    else if (a[1] == "sub" && a[2] == "sp" && a[3] == "sp" && a[4] ~ /^#/) n += imm(a[4]) * (a[6] == "#12" ? 4096 : 1)
    else if (a[1] == "sub" && a[2] == "x9" && a[3] == "sp" && a[4] ~ /^#/) x9 = imm(a[4]) * (a[6] == "#12" ? 4096 : 1)
    else if (a[1] == "cmp" && a[2] == "sp" && a[3] == "x9") loop = 1
  }
  END { flush() }' | sort -rn
}

if [ "${1:-}" = --self-test ]; then
  t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
  { echo 'declare void @use(ptr)'
    for n in 33000 9000 300; do
      echo "define void @f$n() #0 { %a = alloca [$n x i8], align 16
  call void @use(ptr %a)
  ret void }"
    done
    echo 'attributes #0 = { "probe-stack"="inline-asm" "frame-pointer"="non-leaf" }'; } > "$t/f.ll"
  "$(dirname "$OBJDUMP")/llc" -O2 -mtriple=aarch64-none-elf -filetype=obj "$t/f.ll" -o "$t/f.o"
  got=$(frames "$t/f.o" | tr '\t\n' ' ;')
  # f33000: probe loop to sp-0x8000 + 0xf0 + 0x20 pushed; f9000: 2 unrolled pages + 0x330 + 0x20; f300: one sub
  want='33040 f33000;9040 f9000;336 f300;'
  [ "$got" = "$want" ] || { echo "check-elf self-test FAILED: got '$got', want '$want'"; exit 1; }
  echo "check-elf self-test ok"; exit 0
fi

ELF=${1:-$REL/ldn-tunnel}
NSP=${2:-$REL/ldn-tunnel.nsp}
for f in "$ELF" "$NSP"; do [ -f "$f" ] || { echo "missing $f: run make nsp"; exit 2; }; done
frames=$(frames "$ELF")

echo "largest stack frames (limit $FRAME_MAX bytes):"
head -10 <<<"$frames" | awk -F'\t' '{ printf "  %7d  %s\n", $1, substr($2, 1, 110) }'
over=$(awk -F'\t' -v max="$FRAME_MAX" '$1 > max' <<<"$frames" | wc -l)
size=$(stat -c %s "$NSP")
echo "exefs.nsp: $size bytes (limit $NSP_MAX)"
# end of the highest section (Idx Name Size VMA Type rows), page-rounded, + main thread stack
image=$("$OBJDUMP" -h "$ELF" | awk '$1 ~ /^[0-9]+$/ && NF >= 5 { e = strtonum("0x" $4) + strtonum("0x" $3); if (e > m) m = e } END { print int((m + 4095) / 4096) * 4096 }')
stack=$(( $(grep -o '"main_thread_stack_size": *"0x[0-9a-fA-F]*"' crates/sys/main.json | grep -o '0x[0-9a-fA-F]*') ))
mem=$((image + stack))
echo "static memory: $mem bytes = image $image + main stack $stack (limit $MEM_MAX)"

rc=0
[ "$over" -eq 0 ] || { echo "FAIL: $over function(s) with a stack frame over $FRAME_MAX bytes (move big buffers to the heap or a static)"; rc=1; }
[ "$size" -le "$NSP_MAX" ] || { echo "FAIL: exefs.nsp is $size bytes, over $NSP_MAX"; rc=1; }
[ "$mem" -le "$MEM_MAX" ] || { echo "FAIL: static memory is $mem bytes, over $MEM_MAX"; rc=1; }
[ "$rc" -ne 0 ] || echo "ok"
exit $rc

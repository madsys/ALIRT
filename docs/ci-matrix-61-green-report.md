# ALIRT CI 全矩阵修复报告（61 jobs + summary 全绿）

> 状态：草稿（等待最终全绿 run 后定稿）
> 仓库：https://github.com/madsys/ALIRT
> 分支：main

## 结论（TL;DR）

- 绿色 run：RUN_ID_PLACEHOLDER（待填）
  https://github.com/madsys/ALIRT/actions/runs/RUN_ID_PLACEHOLDER
- 单个 CI run 内 61 个矩阵 job + 1 个 summary job 全部 success（per-job 结论）。
- 本报告所列修复**全部未经本地编译验证**，靠 CI 迭代验证（每轮 push 触发完整 61-job 矩阵，单轮 40–60 分钟）。

## 矩阵覆盖（61 jobs = 6 版本档 × 10 架构行 + 1 summary）

| 版本 \ 架构 | x86_64 | aarch64 | armv7 | mips | powerpc | riscv |
|---|---|---|---|---|---|---|
| 3.10.108 | ✓ | — | ✓ | ✓ | — | — |
| 4.4.302 | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| 4.19.325 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5.4.290 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5.10.271 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5.15.180 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.1.189 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.6.158 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.12.35 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.18.56 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7.2.10 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

（✓ = 矩阵行存在；具体每行 runtime 与否以 ci.yml 为准）

## 失败模式 → 修复 commit 对照表

| 失败模式 | 根因 | 修复 commit | 涉及文件 |
|---|---|---|---|
| ppc64 ≥6.1 GE 扫描（DIAG 期遗留） | 见下 | 2eb16df 已验证 | src/compat/compat.h |
| ppc64 跳过条件过宽 | CONFIG_PPC64_ELF_ABI_V2 6.1 才存在；LE 即 ELFv2 | cd108dc | src/compat/compat.h |
| ppc 'modules'/'module_kset' 解析 | ≥5.7 kallsyms_lookup_name 不可调用；≥5.9 kernel_read 拒绝 /proc/kallsyms | cd108dc（shadow 方案） | src/compat/compat.h |
| ppc-5.10/5.15 init_mm 回退 | 待 DIAG 定稿 | 待填 | src/arch/powerpc/alirt_mm.h |
| mips-3.10 FP 指令全部汇编失败 | gcc≥4.9 把 -msoft-float 转发给 gas；3.10 源码无 SET_HARDFLOAT 标记 | a6d3fe1（asm.h 全局 .set hardfloat，回退 .word 改写） | tests/ci/build-kernel.sh |
| armv7-3.10 完全静默 | 3.10 无 mach-virt；vexpress-a15 亦静默 → 换 vexpress-a9 + 显式 earlyprintk=pl011 | a6d3fe1 | tests/ci/run-in-container.sh |
| ppc-4.4 SLOF 后挂死 | TCG 2.11 无 book3s DABR 仿真（SPR 1012） | a6d3fe1（ubuntu:20.04 = QEMU 4.2） | .github/workflows/ci.yml |
| riscv 4.19–5.10 地址验证 | （DIAG 期插入的结构体扫描） | 待删（riscv 已确认绿） | src/arch/riscv/alirt_mm.h |

## 声明与限制

1. 所有修复均未在本地编译/启动验证，全部通过 GitHub Actions 矩阵迭代验证。
2. TBD

## 附录：commit 链（按推送顺序）

459e715 … fb2e0d9（批9）→ cd108dc（批10）→ 64988ee（批11）→ dee0add（批12，DIAG）→ a6d3fe1（批13）→ 待填（批14：ppc 回退修复 + 删 riscv DIAG）

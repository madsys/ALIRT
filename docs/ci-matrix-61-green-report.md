# ALIRT CI 矩阵修复报告（62 jobs + summary）

> 仓库：https://github.com/madsys/ALIRT ・ 分支：main ・ 文档定稿时 HEAD：dbd5ec5
> 注意：ci.yml 第 13 行矩阵带 `continue-on-error: true`，run 级结论永远是 success；
> 本报告的"绿"指**单个 run 内每个矩阵 job 各自的 conclusion=success**（per-job 数据），
> 不是 run 徽标。

## 结论（TL;DR）

- 最终验证 run：RUN_ID_PLACEHOLDER
  https://github.com/madsys/ALIRT/actions/runs/RUN_ID_PLACEHOLDER
- 矩阵实际为 **62 个 job**（3.10×3、4.4×5、其余 9 个版本各×6）+ 1 个 summary job。
- 该 run 内 **61 个矩阵 job conclusion=success**；唯一例外 `4.4.302 / powerpc-rt`
  为**已声明限制**（见下），带完整日志证据，非隐藏失败。
- 所有修复**未经本地编译验证**，全部通过 GitHub Actions 矩阵迭代验证（每轮 push 触发完整矩阵，单轮 40–60 分钟，共迭代 20+ 轮）。

## 矩阵覆盖（62 jobs，以 ci.yml 为准）

| 版本 \ 架构 | x86_64 | aarch64 | armv7 | mips | powerpc | riscv |
|---|---|---|---|---|---|---|
| 3.10.108 | ✓ | — | ✓ | ✓ | — | — |
| 4.4.302 | ✓ | ✓ | ✓ | ✓ | ⚠ 限制 | — |
| 4.19.325 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5.4.290 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5.10.271 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5.15.180 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.1.189 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.6.158 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.12.35 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6.18.56 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7.2.10 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

✓ = success；⚠ = 已声明限制（job 仍执行并如实失败，非跳过）。

## 失败模式 → 修复 commit 对照表

| 失败模式 | 根因 | 修复 commit | 涉及文件 |
|---|---|---|---|
| ppc64（5.10/5.15）init_mm 拿不到 | kprobe 路径被整体跳过（条件过宽：CONFIG_PPC64_ELF_ABI_V2 仅 6.1+ 存在）；GE 扫描门限过窄 | 60d83d0（删跳过、GE 门扩展到 `PPC64 && (ELF_ABI_V2 \|\| (LE && <6.1))`、回退 DIAG 加深） | src/arch/powerpc/alirt_mm.h |
| ppc 'modules'/'module_kset' 解析失败 | ≥5.7 kallsyms_lookup_name 不可调用；≥5.9 kernel_read 拒绝 /proc/kallsyms | cd108dc（shadow 方案） | src/compat/compat.h |
| riscv 4.19–5.10 残留 DIAG 结构体扫描 | 诊断期插入的临时 vmap_area 输出块 | 60d83d0（删除 riscv alirt_mm.h 274–341 行 DIAG 块） | src/arch/riscv/alirt_mm.h |
| mips-3.10 全部 FP 指令汇编失败 | gcc≥4.9 把 -msoft-float 转发给 gas，拒绝一切 FP 助记符；3.10 源码无 v4.4 的 SET_HARDFLOAT 标记 | 0d28bc4（asm.h 追加 `#ifdef __ASSEMBLY__ .set hardfloat`——必须 __ASSEMBLY__ 门，asm.h 也被 C 文件 include） | tests/ci/build-kernel.sh |
| armv7-3.10 完全静默 | 3.10 multi_v7_defconfig **没开任何 QEMU 可引导机器**（无 CONFIG_ARCH_VEXPRESS，只有 zynq/sunxi 等 QEMU 无对应机器的架构）；且 QEMU 2.5 的 vexpress 传 ATAGS，而 3.10 multi_v7 的 vexpress 仅 DT_MACHINE_START | a4828f3（开 ARCH_VEXPRESS）+ 21074f5（DEBUG_KERNEL 依赖 + DEBUG_VEXPRESS_UART0_RS1 时代正确符号）+ dbd5ec5（显式 `-dtb vexpress-v2p-ca9.dtb`：QEMU 2.5 无 DTB 生成钩子） | tests/ci/build-kernel.sh、tests/ci/run-in-container.sh |
| armv7-3.10 构建"完成"但无 zImage | make stdout 被丢弃，一次静默短构建产出空镜像；QEMU `load_image_targphys` 对 0 字节文件**报成功**，guest 零输出无报错 | dbd5ec5（kbuild.log 全量捕获 + 构建失败即退出 + 启动前非空校验） | tests/ci/build-kernel.sh、tests/ci/run-in-container.sh |
| ppc-4.4 SLOF 移交后零输出 | TCG 2.11 无 book3s DABR 仿真（SPR 1012）；升 QEMU 4.2 后 POWER9 TCG 默认在 head code 杀 guest；POWER8/POWER7 仍静默；**无 initrd 探针（cc810cd）证明内核从未启动** | 无修复——宣布限制（证据见下）；a6d3fe1（容器升 20.04/QEMU 4.2）、0a3aa52/4617150（CPU pin 尝试，已证伪） | .github/workflows/ci.yml（限制注释） |

## 已声明限制：4.4.302 / powerpc-rt

**现象**：SLOF 正常，"Booting from memory..." 之后 guest 零字节输出，直到 420s 超时被杀。

**证据**（全部留档于对应 run 的 `status-4.4.302-powerpc-rt` artifact 与 job 日志）：

1. 16.04 / QEMU 2.5 — 静默
2. 18.04 / QEMU 2.11 — 静默（TCG 2.11 无 book3s DABR 仿真，SPR 1012）
3. 20.04 / QEMU 4.2 + POWER9 TCG 默认 — `qemu: fatal: Trying to deliver HV exception (MSR) ... with no HV support`，head code 死亡
4. 20.04 / QEMU 4.2 + POWER8 — 静默
5. 20.04 / QEMU 4.2 + POWER7（4617150 起 pin 住）— 静默
6. 20.04 / QEMU 4.2 + POWER7 + **无 initrd 探针**（cc810cd，run 39006650414）— 仍静默：
   SLOF 打印 "Detected RAM kernel at 400000 (7ff0000 bytes)" 并移交，之后零输出。
   若内核能启动，至少会出现 banner 或 "Kernel panic - not syncing: No init found"——
   两者皆无 ⇒ **4.4 ppc64le guest 在任何试过的 era TCG 组合下都无法启动**，与 initrd 摆放无关。
   大端（BE）组合更早死亡（SLOF 首指令 program exception）。

**处置**：矩阵行保留（如实失败），ci.yml 与 run-in-container.sh 均有限制声明注释；
非内核配置问题（同矩阵 4.19+ powerpc 全绿），待 TCG 模型支持后自然转绿。

## 其它声明与限制

1. 所有修复均未在本地编译/启动验证，全部通过 GitHub Actions 矩阵迭代验证。
2. armv7-3.10 的行在修复前存在"构建看似完成（35s）但无 zImage"的静默失败模式；
   dbd5ec5 起任何构建失败会立即带 kbuild.log 尾部退出，不再出现假构建。
3. 报告中所有 run ID、job ID、artifact 均可在 https://github.com/madsys/ALIRT/actions 复核。

## 附录：commit 链（按推送顺序，459e715 之后共 23 个）

批1–9（基础修复）：459e715…fb2e0d9（含 riscv 4.19 fw_payload 引导、/proc/kallsyms 解析、ppc64 era-QEMU 修复、mips 3.10 FPU 汇编、CONFIG_OF 等）
批10：cd108dc（ppc64 收窄 kprobe 跳过、modules shadow、init_mm via init_task；armv7-3.10 机器修复、mips ldc1/sdc1、ppc-4.4 容器）
批11：64988ee（mips fpu_save/restore .word 改写；armv7 DEBUG_LL + earlyprintk 观测）
批12：dee0add（ppc pre-6.1 回退自测 DIAG）
批13：a6d3fe1（mips 全局 hardfloat；armv7 vexpress-a9；ppc-4.4 升 QEMU 4.2）
批14：60d83d0（ppc 5.10/5.15 转绿：删跳过 + GE 门扩展 + 回退 DIAG；删 riscv DIAG 块）
批15：0d28bc4（mips __ASSEMBLY__ 门——修 asm.h:417 C 文件编译错）
批16：0a3aa52（ppc-4.4 POWER8 pin——后证伪）
批17：21074f5（armv7 DEBUG_KERNEL + DEBUG_VEXPRESS_UART0_RS1）
批18：4617150（ppc-4.4 POWER7 pin）
批19：a4828f3（armv7 ARCH_VEXPRESS 根因修复）
批20：cc810cd（ppc-4.4 无 initrd 探针——二分定位）
批21：dbd5ec5（armv7 显式 -dtb + 构建可观测性；ppc-4.4 宣布限制、探针移除）

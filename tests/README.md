# ALIRT Automated Test Facility

A three-layer test pyramid, all driven by GitHub Actions (`.github/workflows/ci.yml`):

## 1. Build matrix (every push / PR)

Each kernel version uses an era-matched distribution container (compiler and
kernel from the same era). The full kernel is built from kernel.org sources
and then the ALIRT modules are compiled against it:

| Kernel | Container | Arch |
|---|---|---|
| 3.10.108 | centos:7 (gcc 4.8) | x86_64 |
| 4.4.302 | ubuntu:16.04 (gcc 5.4) | x86_64 |
| 4.19.325 | ubuntu:18.04 (gcc 7.5) | x86_64 |
| 5.4.290 | ubuntu:20.04 (gcc 9.3) | x86_64 |
| 5.15.180 | ubuntu:22.04 (gcc 11) | x86_64 / aarch64 |
| 6.12.35 | ubuntu:24.04 (gcc 13) | x86_64 / aarch64 |

## 2. QEMU runtime-detection test (each x86_64 kernel version)

Boot a VM with the bzImage built in step 1 plus a busybox initramfs:

1. `insmod hide_self.ko` — the self-hiding sample module (imitates the
   `list_del(&THIS_MODULE->list)` technique of Diamorphine/KoviD; for
   testing only — never load it on a real machine);
2. `insmod mod_hunter.ko`;
3. Assert that a stray struct module flagged with the `Warning` verdict is
   detected → prints `RESULT: PASS/FAIL`.

## 3. Compatibility matrix summary

Every run automatically generates a Markdown table of
"kernel version × arch × build × QEMU runtime"; see the Summary tab of the
Action run page.

## Local manual reproduction (Linux / WSL2)

```bash
# Build one test kernel (6.12.35 as an example)
docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 bash tests/ci/run-in-container.sh 6.12.35 x86_64 true
```

## Directory guide

- `ci/build-kernel.sh` — build a kernel from kernel.org sources
- `ci/run-in-container.sh` — full in-container pipeline (deps → kernel → build → QEMU test)
- `init` — /init test script for the initramfs
- `samples/hide_self.c` — self-hiding sample module (TEST-ONLY)

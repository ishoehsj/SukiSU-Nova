# patches/

按文件名顺序应用于 SukiSU Nova 源码树根目录（`git apply --check` 逐补丁预检，CI 亦如此）。

| 补丁 | 大小 | 目标文件 | 说明 |
|---|---|---|---|
| `00-ci-smoke.patch` | 365 B | — | CI 冒烟用，验证补丁通道可用 |
| `20-selinux-hide-equalize.patch` | 11,535 B | `kernel/feature/selinux_hide.c` | SELinux Hide 时序抖动控制器：等值化 + 0–15 tick 随机自旋 + 2 tick 定向偏置。详见 [docs/zh/timing-jitter.md](../docs/zh/timing-jitter.md) / [docs/timing-jitter.md](../docs/timing-jitter.md) |

## 关于 20 号补丁

它同时包含两代改动（等值化、随机抖动、定向偏置）——**不要拆分**：CI 对每个补丁独立执行 `git apply --check`，而这三层都修改同一批 `my_setprocattr()` 返回路径，拆开会让任意单个补丁无法单独应用。

- 补丁基准：上游 pristine 的 `selinux_hide.c`（`index 1e4ee63..9b748ab`）。
- 只改一个文件，回滚即 `git checkout -- kernel/feature/selinux_hide.c`。
- 参数（`KSU_SETPROC_JITTER_TICKS` / `KSU_SETPROC_BIAS_TICKS`）在文件头部宏定义处，可直接调整。

```bash
git apply patches/20-selinux-hide-equalize.patch
```

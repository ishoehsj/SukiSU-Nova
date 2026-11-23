# SELinux Hide 时序抖动控制器

**补丁**：[`patches/20-selinux-hide-equalize.patch`](../patches/20-selinux-hide-equalize.patch) · 11,535 B · 针对 `kernel/feature/selinux_hide.c` 的 pristine 版本
**用户态配套**：[ishoehsj/kernel-jitter](https://github.com/ishoehsj/kernel-jitter)（v1.3.1，可选）

---

## 1. 摘要

`selinux_hide` 的 `/proc/self/attr/current` 写入钩子存在一条**可被计时的分支差**：两个等长载荷走不同代码路径，回包耗时相差几十到几百纳秒。时序类检测器（Duck Detector、Maple 等）正是用这个差值判断设备是否处于 hook 环境。

本补丁做三件事，全部作用在 `kernel/feature/selinux_hide.c`：

| 层 | 名称 | 作用 |
|---|---|---|
| 1 | 等值化（equalize） | 让两个载荷走**同一条**校验路径，把固有差值从「结构差」压到「噪声」 |
| 2 | 随机抖动（jitter） | 每次探测出口自旋 `0..15` 个硬件计数器 tick，把残余差值摊进一个更宽的窗口 |
| 3 | 定向偏置（bias） | 给可被单独识别的 B 载荷固定加 `2` tick，把「A 快于 B」的符号钉死在原厂方向，避免 ±1 ns 随机翻转判定 |

三层叠加后：单次配对的符号稳定（方向确定，不再抛硬币），但**差值宽度**仍然随机，不能被当作指纹重复采样。

---

## 2. 背景：A / B 两个载荷

检测器对 `/proc/thread-self/attr/current` 连续写入两个**等长**载荷：

```
A = "u:r:__selinux_hide_probe_invalid__:s0"   未知 type，正常字段结构
B = "\n:r:__selinux_hide_probe_invalid__:s0"  首字节是换行，type 字段无法解析
```

原厂内核对两者都返回 `-EINVAL`，但代价不同：

- **A** 进入 `security_context_to_sid()`，做完整的字符串 → SID 解析，在 `symtab_search()` 上失败；
- **B** 因为首个字节是换行，原 `selinux_setprocattr()` 直接跳过转换，只在 `prepare_creds()` 之后的空 SID 检查处失败。

于是 `mean(A) / mean(B)` 稳定偏离 1.0，形成可重复的时序特征。Duck Detector 的判据（原文）是：

> Danger if either direction exceeds 3 × (opposite direction + ties)

即：把同一组载荷重复采样 N 次，统计「A 慢于 B」「A 快于 B」「完全相等」的次数；任一方向的次数超过反向与平局之和的 3 倍，即判定存在可复现的时序不对称。

---

## 3. 第 1 层：等值化

补丁把 `my_setprocattr()` 里原本分散的失败路径收敛到一处：

```c
static int ksu_setproc_context_lookup(const void *value, size_t size,
                                      struct selinux_policy *policy,
                                      u32 *ctx_len, u32 *sid);
```

它依次做：

1. `ksu_setproc_ctx_prepare()` —— 把载荷复制到私有内存（栈 256 B / 堆最大 `KSU_SETPROC_CTX_MAX` 4096 B），剥掉**单个**尾部换行，绝不修改调用者的缓冲区；
2. `ksu_setproc_type_gate()` —— 取第三个 `:` 字段作为 type，在转换所用的同一份 `policy->policydb.p_types` 上 `symtab_search()`；未知 type 或 attribute 直接返回 `-EINVAL`；
3. `security_context_to_sid_live()` —— 与上游一致的真正转换；`-EAGAIN`（stale type mark）时保持原来的双解析分支。

结果：A 和 B 都在第 2 步之前失败，执行**相同指令、同一次 symtab 探测**，都发生在 `prepare_creds()` 之前，代价不再随载荷分叉。返回 0 只表示「交给真正的转换判断」——user / role / MLS、role-type 合法性仍由 `security_context_to_sid_live()` 校验，合法上下文照常切换 SID。

---

## 4. 第 2 层：随机抖动

```c
#define KSU_SETPROC_JITTER_TICKS 16

static inline void ksu_setproc_jitter(void)
{
#if defined(CONFIG_ARM64)
    u64 start, now;
    u32 delay;

    asm volatile("isb; mrs %0, cntvct_el0" : "=r"(start));
    delay = (u32)((start * 0x9E3779B97F4A7C15ULL) >> 60);

    do {
        asm volatile("isb; mrs %0, cntvct_el0" : "=r"(now));
    } while ((now - start) < (u64)delay);
#endif
}
```

- 计数器读的是 `cntvct_el0`：本机 19.2 MHz，**1 tick = 52.083 ns**。
- `delay = (start × 2^64/φ) >> 60` 取的是计数器自身的低位，落在 `0..15`，不需要随机数发生器、不持有锁。
- 自旋上限 `16 tick ≈ 833 ns`，实际平均 `7.5 tick ≈ 390 ns`，相对一次 `setprocattr` 是「几十 ns 级差值 + 百 ns 级扰动」，把原本 1–2 tick 的固定差摊进 16 tick 的窗口里。

调用点：`my_setprocattr()` 里**所有由载荷决定成败的出口**（`ksu_setproc_exit()`，共 6 处）——AVC 拒绝、转换失败、空 SID、`prepare_creds()` 失败等。`uid < 10000`、`name` 不匹配、`size > 4096`、备份策略不可用这四条 `goto call_orig` 的路径**不抖动**，保持原厂行为与零额外开销。

---

## 5. 第 3 层：定向偏置

等值化之后，配对差值落在噪声底：同一台设备上可能这次 `-1 ns`、下次 `+1 ns` —— 比 tick 小四十倍。只读符号的检测器于是**在两次扫描之间翻转结论**，这是最麻烦的形态：不可复现，但会周期性报 Danger。

B 载荷是**自识别**的：首字节就是那个让 type 无法解析的换行。所以给它固定加 2 tick：

```c
#define KSU_SETPROC_BIAS_TICKS 2

static inline int ksu_setproc_bias_arm(void *value, size_t size)
{
    if (!value || size < 2)
        return 0;
    return ((const char *)value)[0] == '\n';
}

static inline void ksu_setproc_exit(void *value, size_t size)
{
    ksu_setproc_jitter();
    if (ksu_setproc_bias_arm(value, size))
        ksu_setproc_spin_ticks(KSU_SETPROC_BIAS_TICKS);
}
```

`2 tick ≈ 104 ns`：足以稳定压过噪声（让 A 快于 B 成为确定性结论，与原厂方向一致），又远小于检测器用来判 Danger 的量级阈值；而随机部分仍在，差值宽度**不可重复采样**。

---

## 6. 参数

| 宏 | 值 | 含义 | 调大 | 调小 |
|---|---|---|---|---|
| `KSU_SETPROC_JITTER_TICKS` | 16 | 随机自旋上限（tick） | 抗采样更强，单次 syscall 延迟增加 | 开销更低，抗采样更弱 |
| `KSU_SETPROC_BIAS_TICKS` | 2 | B 载荷额外固定 tick | 方向更硬，但差值宽度变粗 | 方向可能被噪声淹没 |
| `KSU_SETPROC_CTX_MAX` | 4096 | 参与等值化的载荷上限 | — | 超限载荷走 `call_orig`，不参与等值化 |
| `KSU_SETPROC_CTX_STACK` | 256 | 栈缓冲阈值，超过则 `kmalloc` | — | — |
| `KSU_SETPROC_TYPE_MAX` | 128 | type 字段最大长度 | — | 超长 type 交给完整解析器决定 |

---

## 7. 实测

设备：OnePlus PLK110 / Android 17 / `6.12.69-android16-6`，计数器 19.2 MHz。

### 7.1 判据与统计口径

Duck Detector 报告中的两行 `ksu_types timing with invalid types`：

| 行 | 采样点 |
|---|---|
| 1 | 普通 `setprocattr` 路径 |
| 2 | `setprocattr` 专用路径（检测器自己走 `write()` 计时的分支） |

每行给出 `A>B` / `A<B` / `A=B` 三个计数，判据是任一方向 > 3 × (反向 + 平局)。

### 7.2 三层叠加前后

| 版本 | 行1（A>B / A<B / 平局） | 行2（A>B / A<B / 平局） | 判定 |
|---|---|---|---|
| 原厂 `selinux_hide` | 817 / 10061 / 2622 | 1386 / 10759 / 1355 | 两行 Danger（行1 A:B = 1:12.3，行2 1:7.76） |
| +等值化 +随机抖动 | 2408 / 5665 / 5427 | 5601 / 7274 / 625 | 两行均回落到判据的 24.1% / 38.9% |
| +定向偏置 2 tick（当前） | 占用 19.4–36.8% | 占用 36.8–41.4% | 连续 8 次扫描 **8/8 Danger 0** |

「占用」= 该方向计数 ÷ 3 × (反向 + 平局)：越低越安全，100% 即踩线。

### 7.3 单次配对探针

同一组载荷重复 512 次、每次 8 对（`pairs=512`）：

```
medA = 2343 tick   medB = 2292 tick   diff = 51 tick   ratio(med) = 1.0223
平局占比 82.9%，A 慢占比 11.95%，errno 两侧均为 22（EINVAL）
```

即：绝大多数配对差值落在统计噪声里，可判读的方向差异只占约一成，且方向由偏置决定、不随运行变化。

### 7.4 Duck Detector 整体

```
Overall Status  [▲ WARNING]      Danger 0 / Warning 2 / Ready 20
SELinux         [✔ CLEAR]        Enforcing
SELinux Hide attr/current timing: No reproducible asymmetry
                                 (Pairs=256, A med 2343, B med 2292, p10/med/p90 = -469/0/469)
```

剩余两条 Warning 是 `ADB Runtime`（USB 调试开着）与 `System Properties`（1 个属性信号待复核），与 SELinux 时序无关。

---

## 8. 自验

1. **看符号与宽度**：连续导出 3–5 份 Duck Detector 完整报告，确认两行都停在判据的 50% 以内，且 `A>B`/`A<B` 的方向不翻转。
2. **看单次配对**：自建探针对 `/proc/thread-self/attr/current` 交替写 A/B 各 512 次，统计中位差；应看到 `diff` 稳定为正（A 慢于 B）但数值随运行抖动。
3. **看指令**：`objdump` 反汇编 `kernelsu.ko`，`ksu_setproc_jitter` 与 `ksu_setproc_spin_ticks` 里应有 `mrs xN, cntvct_el0` 与 `isb` 成对出现。

---

## 9. 应用与回滚

补丁针对 `kernel/feature/selinux_hide.c` 的 pristine 版本，仓库内 CI 以 `git apply --check` 逐补丁预检，因此**不要拆成两个补丁**，也不要与 `30-*.patch` 之类的旧代抖动补丁叠加。

```bash
# 在 SukiSU-Nova 源码树根目录
git apply patches/20-selinux-hide-equalize.patch
```

回滚即 `git checkout -- kernel/feature/selinux_hide.c`（本补丁只动这一个文件）。设备侧回滚走刷回原厂 `init_boot`，与补丁无关。

可选：`kernel-jitter` 用户态模块（v1.3.1）用于对已加载检测库的进程做采样点替换，与内核侧补丁互不依赖，可单独使用。

---

## 10. 许可

`kernel/` 下补丁遵循 GPL-2.0-only（与 SukiSU Nova 内核目录一致）。

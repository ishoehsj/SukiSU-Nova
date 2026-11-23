# SELinux Hide timing-jitter controller

**Patch**: [`patches/20-selinux-hide-equalize.patch`](../patches/20-selinux-hide-equalize.patch) · 11,535 B · targets the pristine `kernel/feature/selinux_hide.c`
**Companion userspace module**: [ishoehsj/kernel-jitter](https://github.com/ishoehsj/kernel-jitter) (v1.3.1, optional)

---

## 1. What it does

The `/proc/self/attr/current` write hook in `selinux_hide` has a **timable branch split**: two equal-length payloads take different code paths and finish tens to hundreds of nanoseconds apart. Timing detectors (Duck Detector, Maple) read exactly that delta to decide whether the device is hooked.

The patch layers three changes onto that one file:

| Layer | Name | Effect |
|---|---|---|
| 1 | Equalize | Both payloads run the **same** validation path, so the difference stops being structural |
| 2 | Jitter | Every payload-dependent exit spins `0..15` hardware-counter ticks, spreading the residual delta over a wider window |
| 3 | Bias | The self-identifying B payload gets a fixed `+2` ticks, pinning the *sign* to the stock direction |

After all three, a paired comparison has a deterministic direction (no more coin flip between runs) while the *width* of the delta stays random and cannot be used as a fingerprint.

---

## 2. The two payloads

```
A = "u:r:__selinux_hide_probe_invalid__:s0"    unknown type, well-formed fields
B = "\n:r:__selinux_hide_probe_invalid__:s0"   leading newline, type field unparsable
```

Stock returns `-EINVAL` for both, but through different work: A enters `security_context_to_sid()` and fails in `symtab_search()`; B skips conversion entirely because of the leading newline and only fails on the empty SID after `prepare_creds()`. The hook kept that split, which produced a stable A-slower signal.

Duck Detector's criterion, verbatim:

> Danger if either direction exceeds 3 × (opposite direction + ties)

---

## 3. Layer 1 — equalization

All payload-dependent failure paths in `my_setprocattr()` are funnelled into one helper:

```c
static int ksu_setproc_context_lookup(const void *value, size_t size,
                                      struct selinux_policy *policy,
                                      u32 *ctx_len, u32 *sid);
```

1. `ksu_setproc_ctx_prepare()` copies the payload (256 B stack, up to 4096 B heap), strips one trailing newline, never touches the caller's buffer;
2. `ksu_setproc_type_gate()` resolves the third `:` field against the same `policy->policydb.p_types` the conversion will use, rejecting unknown/attribute types with `-EINVAL`;
3. `security_context_to_sid_live()` performs the real conversion, keeping the upstream `-EAGAIN` dual-parse fallback.

Both payloads now fail before `prepare_creds()` on the same instructions and the same single symtab probe. A zero return only means "let the real conversion decide": user, role, MLS and role/type validity are still enforced, and a valid context still switches the current SID.

---

## 4. Layer 2 — random jitter

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

- `cntvct_el0` runs at 19.2 MHz here: **one tick = 52.083 ns**.
- `delay` derives from the counter's own low bits (`0..15`); no RNG, no locks.
- Spin budget is 16 ticks ≈ 833 ns (mean ≈ 390 ns), which swallows a 1–2 tick structural delta.

Called from all six payload-dependent exits (`ksu_setproc_exit()`): AVC denial, failed conversion, empty SID, failed `prepare_creds()`, and the two post-cred checks. The four `goto call_orig` paths — `uid < 10000`, name mismatch, `size > 4096`, missing backup policy — stay untouched and cost nothing.

---

## 5. Layer 3 — directional bias

Once equalized, the paired delta sits on the noise floor: `-1 ns` on one run, `+1 ns` on the next, forty times below a tick. A checker that only reads the sign then flips its verdict between scans on unchanged hardware — irreproducible, but periodically red.

B is self-identifying by its leading newline, so it gets a fixed two extra ticks:

```c
#define KSU_SETPROC_BIAS_TICKS 2
```

2 ticks ≈ 104 ns: enough to make "A faster than B" deterministic and to match the stock direction, far below the magnitude a Danger verdict needs, while the random part still keeps the delta width unpredictable.

---

## 6. Parameters

| Macro | Value | Meaning |
|---|---|---|
| `KSU_SETPROC_JITTER_TICKS` | 16 | Max random spin in ticks |
| `KSU_SETPROC_BIAS_TICKS` | 2 | Extra fixed ticks for the B payload |
| `KSU_SETPROC_CTX_MAX` | 4096 | Payloads above this fall back to `call_orig` |
| `KSU_SETPROC_CTX_STACK` | 256 | Stack buffer before `kmalloc` |
| `KSU_SETPROC_TYPE_MAX` | 128 | Max type-field length handled by the gate |

---

## 7. Measured result

Device: OnePlus PLK110, Android 17, `6.12.69-android16-6`, 19.2 MHz counter.

| Version | Row 1 (A>B / A<B / ties) | Row 2 (A>B / A<B / ties) | Verdict |
|---|---|---|---|
| Stock `selinux_hide` | 817 / 10061 / 2622 | 1386 / 10759 / 1355 | Danger on both rows (A:B = 1:12.3 and 1:7.76) |
| + equalize + jitter | 2408 / 5665 / 5427 | 5601 / 7274 / 625 | Both rows at 24.1% / 38.9% of the criterion |
| + 2-tick bias (current) | 19.4–36.8% of criterion | 36.8–41.4% of criterion | **8/8 scans Danger 0** |

Paired probe, 512 pairs × 8: `medA = 2343`, `medB = 2292`, `diff = 51` ticks, `ratio(med) = 1.0223`, ties 82.9%, errno `EINVAL` on both arms.

Final Duck Detector run:

```
Overall Status  [▲ WARNING]      Danger 0 / Warning 2 / Ready 20
SELinux         [✔ CLEAR]        Enforcing
SELinux Hide attr/current timing: No reproducible asymmetry
                                 (Pairs=256, A med 2343, B med 2292, p10/med/p90 = -469/0/469)
```

The two remaining warnings are ADB Runtime (USB debugging enabled) and one System Properties signal, unrelated to SELinux timing.

---

## 8. Verifying

1. Export 3–5 Duck Detector reports; both rows should sit under 50% of the criterion and stop flipping direction.
2. Run a paired probe against `/proc/thread-self/attr/current` (512 A/B pairs) and check the median delta: positive and stable in sign, random in width.
3. `objdump` the built `kernelsu.ko`: `ksu_setproc_jitter` / `ksu_setproc_spin_ticks` must contain paired `isb` + `mrs xN, cntvct_el0`.

---

## 9. Applying and reverting

```bash
git apply patches/20-selinux-hide-equalize.patch
```

The patch touches one file only; revert with `git checkout -- kernel/feature/selinux_hide.c`. Do not stack it with older jitter patches (`30-*.patch`) — the repository CI runs `git apply --check` on each patch independently, which is why both generations live in this single file.

---

## 10. License

Patches under `kernel/` follow GPL-2.0-only, matching the SukiSU Nova kernel tree.

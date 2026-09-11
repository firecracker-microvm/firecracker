# Bug: RateLimiter「超额消费」亚毫秒债务导致设备 I/O 永久卡死

> 状态：**上游未修复、无人认领**（截至检查时 `main` 仍含缺陷代码）
> 目标文件：`src/vmm/src/rate_limiter/mod.rs`
> 严重度：高（永久 hang，需重启 microVM，不是限速而是停摆）

---

## 1. 一句话概要

`RateLimiter::consume` 在 `OverConsumption` 路径用**毫秒向下取整**计算补偿时间：

```rust
self.activate_timer(Duration::from_millis((ratio * refill_time as f64) as u64));
```

当 `ratio * refill_time < 1` 时截断为 `0`，得到 `Duration::ZERO`。
`TimerFd::arm(Duration::ZERO)` 实际执行 `timerfd_settime(it_value = {0,0})`，会把 timerfd **disarm**；
但 `activate_timer()` 仍无条件把 `timer_active = true`。

于是定时器永不触发 → `event_handler()` 永不成功 → `consume()` 开头的
`if self.timer_active { return false; }` 永远成立 → **限流器永久锁死，设备整条 I/O 队列停止。**

---

## 2. 位置与调用链

### 关键代码

文件：`src/vmm/src/rate_limiter/mod.rs`

```rust
// activate_timer()：无条件置位
fn activate_timer(&mut self, one_shot_duration: Duration) {
    self.timer_fd.arm(one_shot_duration, None);
    self.timer_active = true;          // <-- 即使 arm 的是 0 时长
}

pub fn consume(&mut self, tokens: u64, token_type: TokenType) -> bool {
    if self.timer_active {             // <-- 永久为 true 后直接失败
        return false;
    }
    ...
    match bucket.reduce(tokens) {
        ...
        BucketReduction::OverConsumption(ratio) => {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            self.activate_timer(Duration::from_millis(
                (ratio * refill_time as f64) as u64,   // <-- 亚毫秒被截断为 0
            ));
            true
        }
    }
}
```

文件：`src/utils/src/time.rs` — `TimerFd::arm` 直接把 duration 拆成 sec/nsec，
`Duration::ZERO` → `it_value={0,0}` → 解除定时器（内核语义，不是“立即触发”）。

### 调用链（以 virtio-block 为例）

```
VirtioBlock::process_queue()
  └─ Request::rate_limit()                       // request.rs
       └─ RateLimiter::consume(data_len, Bytes)  // rate_limiter/mod.rs
            └─ TokenBucket::reduce(tokens)
                 └─ tokens > size ⇒ BucketReduction::OverConsumption(ratio)
            └─ activate_timer(Duration::from_millis((ratio*refill_time) as u64))
                 └─ TimerFd::arm(Duration::ZERO)
                      └─ timerfd_settime(it_value = {0,0})   // 定时器被解除
                 timer_active = true                        // 标志却仍置位
```

之后：`consume()` 永远返回 false，timerfd 永不触发，队列永久挂起。
（virtio-net 的 RX/TX 走 `rate_limited_rx_single_frame` / `rate_limiter_consume_op`，同理。）

---

## 3. 触发条件

设单次请求 `D` 字节、桶容量 `S`、回填时间 `T`(ms)，且消费时桶满：

```
D > S                 （必须发生 OverConsumption）
D - S < S / T         （超额量足够小，使 (D-S)/S * T < 1）
```

| 场景 | 设备 | size | refill_time | 触发请求 | excess | ratio*T (ms) | 截断 |
|---|---|---|---|---|---|---|---|
| block（推荐） | virtio-blk | 4095 | 1 | 4096B direct read | 1 | 0.000244 | **0** |
| block 变体 | virtio-blk | 511 | 1 | 512B sector read | 1 | 0.00196 | **0** |
| block 变体 | virtio-blk | 1048576 | 10 | 1MiB+512B read | 512 | 0.0049 | **0** |
| net | virtio-net TX | 1500 | 1 | 1489B eth frame | 1 | 0.000667 | **0** |

> Ops 桶不会触发（`tokens` 恒为 1，不可能 `> size`）；只有带宽（Bytes）桶会中招。

---

## 4. 影响

- **不是限速，而是永久卡死**：`event_handler` 走 `WouldBlock` 分支只会返回
  `SpuriousRateLimiterEvent`，不会清 `timer_active`。
- virtio-block：队列停止，guest 读写永久挂起，`dmesg` 报
  `task blocked for more than 120 seconds`。
- virtio-net：RX/TX 永久停摆。
- 只能重启 microVM 恢复。
- host 侧指纹：`rate_limiter_throttled_events` 持续增长而
  `rate_limiter_event_count` 恒为 0。

---

## 5. 证据

### 5.1 timerfd 语义（C，已运行）

```
it_value = {0,0}      -> 200ms 内无事件（timer 被 disarm）
it_value = {0,1ns}    -> 触发
it_value = {0,500000ns} -> 触发
```

### 5.2 完整算术 + timerfd 复现（C，已运行）

`/tmp/ratelimit_repro.c`（复刻 `TokenBucket::reduce` + `RateLimiter::consume`）输出：

```
1) consume(1000001): request 1 byte larger than the 1 MB bucket
  OverConsumption ratio=0.000001000 -> Duration::from_millis(0)
   consume accepted=1, is_blocked=1
2) wait 200 ms for the timer to fire and unblock...
   NO timer event -> timerfd was disarmed -> limiter stays blocked FOREVER (bug)
3) subsequent consume(1) accepted=0 (0 == permanently throttled)
```

### 5.3 Rust 回归用例

已在 `src/vmm/src/rate_limiter/mod.rs` 的 `mod tests` 中新增
`test_rate_limiter_overconsumption_sub_millisecond`。

---

## 6. 复现步骤

### 6.1 单元级（最快）

```bash
cargo test -p vmm --lib rate_limiter::tests::test_rate_limiter_overconsumption_sub_millisecond
# 修复前：panic(SpuriousRateLimiterEvent)；修复后：pass
```

也可先 `git stash` 掉修复，确认该用例确实失败（证明能抓到 bug）。

### 6.2 端到端（真实 microVM）

1. 准备一块无分区/文件系统的裸盘：

   ```bash
   truncate -s 16M /tmp/scratch.img
   ```

2. `vm_config.json` 中给第二块盘加限流：

   ```json
   {
     "drives": [
       { "drive_id": "rootfs", "path_on_host": "/path/rootfs.ext4",
         "is_root_device": true, "is_read_only": false },
       { "drive_id": "scratch", "path_on_host": "/tmp/scratch.img",
         "is_root_device": false, "is_read_only": false,
         "rate_limiter": {
           "bandwidth": { "size": 4095, "refill_time": 1, "one_time_burst": 0 },
           "ops":       { "size": 100000, "refill_time": 1000, "one_time_burst": 0 }
         } }
     ]
   }
   ```

3. 启动并开启 metrics：

   ```bash
   ./firecracker --api-sock /tmp/fc.sock --config-file vm_config.json \
                 --metrics-path /tmp/fc_metrics
   ```

   `boot-source.boot_args` 两个必要项（基于 vmlinux-5.10.225 实测）：
   - `acpi=off`：否则 ACPI `LNRO0005` 节点与 cmdline `virtio_mmio.device=`
     双重注册同一 MMIO 区域，virtio-mmio probe 报 `-16 (EBUSY)`，`/dev/vda` 不出现；
   - `init=/init`：真实块设备根文件系统，内核默认执行 `/sbin/init` 而非 `/init`。

4. guest 内触发：

   ```sh
   sleep 1     # 让带宽桶回满
   dd if=/dev/vdb of=/dev/null bs=4096 count=1 iflag=direct   # 第一次成功
   dd if=/dev/vdb of=/dev/null bs=4096 count=1 iflag=direct   # 之后永久 hang
   ```

5. host 侧确认指纹：

   ```bash
   curl --unix-socket /tmp/fc.sock -X PUT http://localhost/actions \
        -H 'Content-Type: application/json' \
        -d '{"action_type":"FlushMetrics"}'
   grep -A3 scratch /tmp/fc_metrics
   # rate_limiter_throttled_events 持续增长，而 rate_limiter_event_count 恒为 0
   ```

> 参数原因：`excess = 4096 - 4095 = 1`，`ratio = 1/4095`，
> `ratio*T = 0.000244ms` → 截断为 0；8 扇区请求不会被块层拆分。
>
> ⚠️ 实测（vmlinux-5.10.225）：guest 内核开机分区扫描会读 **4096 字节**，
> 因此在 `size=4095` 下 bug 在**开机时就被分区扫描触发**——之后 guest 第一次
> `dd` 就会 hang（设备开机即不可用），而非“第一次成功、第二次 hang”。
> 这正是 REPORT 中 size=511 变体预告的现象，只是触发者是分区扫描。

### 6.3 已跑通的 e2e 结果（本机，见 fc_e2e_artifacts/）

| | read #1 | read #2 | `throttled_events` | `rate_limiter_event_count` |
|---|---|---|---|---|
| 修复前 | 永久 hang（看门狗 20s 报 BUG CONFIRMED） | — | 1 | **0** |
| 修复后 | 4096 OK | 4096 OK | 0 | 3 |

指纹：`rate_limiter_throttled_events > 0 且 rate_limiter_event_count == 0`。

---

## 7. 修复建议

将毫秒截断改为**纳秒计算 + 向上取整**，保证任何正债务都至少 arm 1ns：

```rust
BucketReduction::OverConsumption(ratio) => {
    // ...
    // Compute the duration in nanoseconds instead of milliseconds and round
    // up. Truncating sub-millisecond debts to zero would call
    // `TimerFd::arm` with a zero `Duration`, which disarms the underlying
    // timerfd while `timer_active` is still set...
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let duration_ns =
        (ratio * refill_time as f64 * NANOSEC_IN_ONE_MILLISEC as f64).ceil() as u64;
    self.activate_timer(Duration::from_nanos(duration_ns));
    true
}
```

理由：`OverConsumption` 路径中 `ratio` 恒 `> 0` 且 `refill_time >= 1`，
`.ceil()` 后 `duration_ns >= 1`，不可能再得到 `Duration::ZERO`。
原有 `test_rate_limiter_overconsumption`（1500ms/500ms）数值不变，无回归。

### 回归用例

```rust
#[test]
fn test_rate_limiter_overconsumption_sub_millisecond() {
    let clock = MockClock::new();
    let mut l = RateLimiter::new_mocked(1_000_000, 0, 1000, 0, 0, 0, &clock);

    // 比满桶多消费 1 字节 -> 借 1 token -> 0.001ms 债务（修复前截断为 0）
    assert!(l.consume(1_000_001, TokenType::Bytes));
    assert!(l.is_blocked());

    // 定时器必须触发并解锁；修复前 timer 被 disarm，这里会 panic
    clock.advance(Duration::from_millis(50));
    l.event_handler().unwrap();
    assert!(!l.is_blocked());
    assert!(l.consume(1, TokenType::Bytes));
}
```

> 采用 `MockClock`（与近期 “deterministic clock for RateLimiter tests” 重构一致），
> 避免真实 `thread::sleep`。修复前该用例 panic 于 `SpuriousRateLimiterEvent`，
> 修复后通过。

---

## 8. 上游状态（提 PR 前须知）

| 项 | 结论 |
|---|---|
| 上游 `main` 是否已修 | ❌ 未修，`OverConsumption` 仍用 `from_millis` |
| 上游 `TimerFd::arm` 是否防 0 | ❌ 未防 |
| 是否有 open issue/PR | ❌ 无（相关标题项均无关） |
| 相关历史 PR | #2048 引入该路径；#2601/#3370 只改 `auto_replenish` 精度 |
| 在途冲突 | ⚠️ `#6123 [blk-threaded - 1/5]` 正在把 `timer_active` 改成 `Arc<AtomicBool>`（不改时间算法）→ 需 rebase，冲突面小 |

**PR 注意**：与 #6123 的重构正交；rebase 时把 `self.timer_active = true`
替换为 `self.timer_active.store(true, Ordering::Relaxed)` 即可。

---

## 9. 参考文件

| 文件 | 作用 |
|---|---|
| `src/vmm/src/rate_limiter/mod.rs` | 缺陷 + 修复 + 回归用例 |
| `src/utils/src/time.rs` | `TimerFd::arm`，`Duration::ZERO` → disarm |
| `src/vmm/src/devices/virtio/block/virtio/request.rs` | `Request::rate_limit`（block 调用点） |
| `src/vmm/src/devices/virtio/net/device.rs` | `process_tx` / `rate_limited_rx_single_frame`（net 调用点） |
| `docs/block.md` | rate_limiter 配置与示例 |

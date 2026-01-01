# 08_driver_model.md

## 目标
- 统一 virtio-block/net/console/时钟 驱动框架与初始化流程。
- 支持 QEMU 设备与实板设备的统一枚举与注册。
- 提供最小 DMA 抽象与中断处理入口，便于模块复用。

## 设计
- 设备枚举优先依赖 DTB：扫描 virtio-mmio 节点与设备树兼容串。
- 驱动注册采用静态表，按 `compatible` 或设备类型匹配驱动。
- 驱动统一入口：`probe -> init -> irq_handler`，驱动返回可用设备句柄。
- DMA 抽象放在 HAL 层：提供物理页分配、缓存同步、地址转换接口。
- 中断注册通过平台层统一映射（如 PLIC/CLINT），驱动只关心 IRQ 号。
- I/O 访问尽量走安全封装（MMIO 访问封装 + volatile 读写）。
- 当前阶段先落地 virtio-blk(mmio) 最小驱动：DTB 枚举、MMIO 映射、单队列同步读写，优先使用 IRQ 完成唤醒（PLIC claim/complete），无 IRQ 时回退轮询。
- virtio-blk 仅实现 read/write 请求，暂不启用多队列与高级特性。
- virtio-net(mmio) 先提供最小 RAW 帧收发：RX/TX 双队列、静态缓冲区、IRQ 触发后由上层轮询取包。

## 关键数据结构
- `DeviceInfo`：设备类型、MMIO 基址、IRQ 号、设备树节点信息。
- `DriverOps`：`probe`、`init`、`handle_irq` 等回调接口。
- `DriverRegistry`：驱动注册表与匹配逻辑。
- `Bus`：设备枚举与资源映射抽象（DTB/Virtio-MMIO）。
- `DmaBuf`：DMA 缓冲区描述（物理地址、长度、缓存一致性标志）。
- `VirtioBlkQueue`：virtio-blk 描述符/avail/used 环队列布局。
- `VirtioNetQueue`：virtio-net RX/TX 描述符环队列布局。

## 关键流程图或伪代码
```text
boot
  -> dtb_scan
  -> for each device_node:
       dev = DeviceInfo::from_dtb(node)
       driver = DriverRegistry::match(dev)
       handle = driver.probe(dev)
       driver.init(handle)
  -> irq_enable

irq_handler(irq)
  -> driver = DriverRegistry::lookup(irq)
  -> driver.handle_irq()
```

## 风险与权衡
- 设备兼容性差异会增加分支判断与维护成本。
- DMA 一致性与缓存刷新的平台差异需要 HAL 支撑。
- 抽象层过多可能影响性能与调试效率。

## 测试点
- QEMU virtio-block：读写镜像、读取分区表、简单文件读写。
- QEMU virtio-net：收发包、自环测试、基础 ping/UDP。
- console：串口输出与输入回显。
- 时钟/中断：定时器中断触发与 IRQ 路径正确性。
- virtio-blk：外部 ext4 镜像挂载后读取 `/init`。

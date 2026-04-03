# sing-openvpn 架构设计与源码分析

## 1. 项目概述

`sing-openvpn` 是一个基于 Go 语言实现的轻量级、高性能、纯用户态 OpenVPN 客户端库。该项目的主要目标是为 `sing-box` 和 `clash` 等代理工具提供原生的 OpenVPN 协议支持，无需依赖操作系统的 TUN/TAP 驱动，也无需 root 权限。

项目通过集成 [gVisor](https://github.com/google/gvisor) 网络栈，在用户空间完成了 IP 数据包的处理，并对外提供了标准的代理拨号接口。

## 2. 核心架构

`sing-openvpn` 的架构可以划分为以下几个主要层级：

- **配置与解析层**：负责读取和解析 `.ovpn` 配置文件，提取证书、密钥、加密算法及服务器节点等信息。
- **传输与多路复用层**：管理底层的 TCP 或 UDP 连接，负责 OpenVPN 协议帧的拆包与封包，并区分**控制通道 (Control Channel)** 与**数据通道 (Data Channel)**。
- **控制通道与握手层**：实现 OpenVPN 特有的可靠控制流（带 ACK 确认机制的滑动窗口），并在其上运行标准 TLS 握手及后续的配置协商 (`PUSH_REQUEST` / `PUSH_REPLY`)。
- **数据通道与加密层**：负责应用层数据的加解密（支持 AES-GCM 和 AES-CBC），以及防重放攻击 (Replay Protection)。
- **虚拟网络层 (TUN)**：利用 gVisor 提供的用户态 TUN 栈，实现 IP 数据包的路由与读写。

## 3. 核心数据流

### 3.1 出站数据流 (Outbound)
1. 应用层通过 `DialContext` 请求建立连接，数据交由 gVisor 网络栈处理。
2. `tun.go` 中的 `tunReadLoop` 批量从 gVisor TUN 读取原生 IP 数据包（明文）。
3. 调用 `cipher.Encrypt` 进行原地加密 (In-place Encryption)。
4. 封装为 OpenVPN 数据包 (`OpDataV1` 或 `OpDataV2`，携带 PeerID)。
5. 通过 `transport.go` 中的 `writePacket` 写入底层 TCP/UDP 连接。

### 3.2 入站数据流 (Inbound)
1. `transport.go` 中的 `readLoop` 从底层网络读取数据。对于 TCP，先读取 2 字节长度头，再读取完整 payload；UDP 则直接读取 Datagram。
2. 解析 OpenVPN Opcode，识别为数据包后，交由 `tun.go` 的 `processIncomingData` 处理。
3. 调用 `cipher.Decrypt` 进行解密，并验证完整性及防重放攻击。
4. （如果收到 OpenVPN 内部的 Ping Magic 报文，则直接回复 Pong，不进入 TUN）。
5. 将解密后的明文 IP 数据包通过 `tunDevice.Write` 注入 gVisor TUN 栈。
6. gVisor 网络栈将 IP 数据包还原为应用层数据流。

## 4. 模块与源码级说明

### 4.1 客户端生命周期 (`client.go`)
- **`NewClientFromFile` / `NewClient`**: 客户端初始化，生成随机的 `SessionID`，初始化 `ControlConn`。
- **`Dial`**: 核心连接逻辑。遍历配置中的 Remote 节点，尝试建立底层网络连接。启动 `readLoop` 协程，然后调用 `performHandshake` 阻塞等待握手完成。握手成功后，初始化 `wireguard.NewStackDevice` (gVisor TUN) 并启动 `tunReadLoop` 和 `pingLoop`。

### 4.2 传输与多路复用 (`transport.go`)
- **`readLoop`**: 持续运行的底层读事件循环。利用 `sync.Pool` 分配内存。对于 `tls-crypt` 加密的连接，会在此处进行 Unwrap 解包。将数据包解析为 `packet.Packet` 对象后调用 `handlePacket` 分发。
- **`handlePacket`**: 
  - `OpControlHardReset*`: 触发握手信号。
  - `OpControlV1`: 控制通道数据，回复 ACK，并写入 `ControlConn` 的读缓冲区。
  - `OpDataV1` / `OpDataV2`: 数据通道，交给 `processIncomingData` 处理。

### 4.3 可靠控制流 (`control.go`)
- **`ControlConn`**: 实现了 `net.Conn` 接口，将不可靠的 UDP Datagram 包装为可靠的字节流，供标准 `crypto/tls` 使用。
- **Write**: 将大的 TLS 记录分片 (Fragment) 避免 IP 分片。对每个控制包分配 `PacketID`，发送后等待 ACK。如果超时则重传（最多重试 5 次）。
- **Read**: 通过条件变量 (`sync.Cond`) 等待 `readLoop` 投递控制通道数据。

### 4.4 握手与协商 (`handshake.go`)
- **`performHandshake`**: 
  1. 互发 `Hard Reset`。
  2. 建立 TLS 连接 (`tls.Client`)。
  3. 执行 `key_method_2` 密钥交换（导出数据通道的 PRF 密钥）。
  4. 发送 `peer-info`。
  5. 发送 `PUSH_REQUEST` 并等待服务器下发 `PUSH_REPLY`（包含分配的 IP、路由、MTU 等）。

### 4.5 数据层与 TUN (`tun.go`)
- **`tunReadLoop`**: 从 TUN 批量读取 IP 数据包 (Batching, 一次最多 32 个包)，加密后发往网络。
- **`processIncomingData`**: 接收网络发来的加密数据，解密后写入 TUN。同时负责拦截和响应 OpenVPN 保活机制 (Ping/Pong)。

### 4.6 内部库 (`internal/`)
- **`internal/crypto/`**:
  - `cipher.go`: 数据通道的 AES-GCM / AES-CBC 接口。
  - `tls_crypt.go`: 实现 `tls-crypt` (V1) 规范，对控制通道包进行额外的 AES-CTR 加密和 HMAC-SHA256 签名，提供抗审查和抗扫描能力。
  - `replay.go`: 基于滑动位掩码 (Bitmask) 的防重放窗口。
- **`internal/packet/`**:
  - `packet.go` / `opcode.go`: OpenVPN 协议头部解析。提取 Opcode、SessionID、PacketID 及 Acks 列表。

## 5. 性能优化设计 (Performance Highlights)

1. **Zero-Allocation 数据面**：
   - 广泛使用 `sync.Pool` (`bufPool`) 复用 64KB 的读写缓冲区。
   - AES 加解密过程采用原地操作 (In-place)，避免堆内存分配 (Heap Allocations)，大幅减轻 GC 压力。
2. **TCP 零拷贝发送**：
   - 在 `writePacket` 中，提前为 TCP 的 2 字节长度头分配空间 (`tcpData := make([]byte, 2+len(data))`)，避免 `append` 导致的内存扩容或多次系统调用。
3. **批量处理 (Batching)**：
   - `tunReadLoop` 中使用 Batch 模式读取虚拟网卡，显著减少跨态系统调用 (Syscall) 的频率，提升高吞吐场景下的性能。
4. **控制通道状态机精简**：
   - 自定义的 `ControlConn` 通过 `sync.Map` 和 `sync.Cond` 实现了高效的 ACK 唤醒和超时重传队列。

## 6. 总结

`sing-openvpn` 是一个架构清晰、模块化良好的网络代理库。通过将复杂的 OpenVPN 状态机（如握手、重传）与数据面（加密、TUN）进行解耦，配合 gVisor 提供的全用户态 TCP/IP 栈，不仅达到了极高的网络吞吐性能，同时也保持了与各种现代代理框架（sing-box）的极佳兼容性。

# OpNet 端口穿透工具

跨平台的端口穿透工具，使用自定义协议和 TLS 加密，避免特征识别。

## 编译

```bash
# 编译服务端
go build -o opnet-server ./cmd/server/

# 编译客户端
go build -o opnet-client ./cmd/client/

# 跨平台编译示例
GOOS=linux GOARCH=amd64 go build -o opnet-server-linux ./cmd/server/
GOOS=linux GOARCH=amd64 go build -o opnet-client-linux ./cmd/client/
GOOS=windows GOARCH=amd64 go build -o opnet-server.exe ./cmd/server/
GOOS=windows GOARCH=amd64 go build -o opnet-client.exe ./cmd/client/
```

## 使用说明

### 服务端

```bash
./opnet-server -token opnet123 -port 2222
```

参数说明：
- `-token`：认证 Token（必填）
- `-port`：基础映射端口（默认 2222），多客户端时自动递增（2223, 2224...）
- `-cport`：控制通道端口（默认 2221）

### 客户端

```bash
./opnet-client -token opnet123 -server 你的服务器IP -netport 22
```

参数说明：
- `-token`：认证 Token（必填，需与服务端一致）
- `-server`：服务端地址，域名或 IP（必填）
- `-netport`：要映射的本地端口（必填）
- `-port`：服务端控制通道端口（默认 2221）
- `-persist`：持久化模式，不自动断开
- `-timeout`：超时时间（小时），默认 2 小时后自动断开

### 使用示例

将本地 SSH (22端口) 映射到服务端 2222 端口：

```bash
# 服务端
./opnet-server -token opnet123 -port 2222

# 客户端
./opnet-client -token opnet123 -server example.com -netport 22

# 外部访问
ssh -p 2222 user@example.com
```

持久化连接（不自动断开）：

```bash
./opnet-client -token opnet123 -server example.com -netport 22 -persist
```

## 安全特性

- TLS 1.3 加密控制通道，外观与普通 HTTPS 流量一致
- 自定义二进制帧协议，无已知穿透工具特征
- 心跳间隔随机化（30-60秒），避免定时特征
- Token 认证机制（常量时间比较）
- **数据通道基于 token 的 HMAC-SHA256 认证**：`MsgNewConn` 载荷携带
  `HMAC(token, magic|clientID|connID)`，未持有 token 的连接无法接入映射端口
- 会话标识不可预测：`clientID`、`connID`、`magic` 均为随机值，
  控制帧与数据帧均校验会话 `magic`

> 协议版本：当前为 **v2**。v2 与 v1 不兼容（v1 数据通道无任何认证），
> 混用时会在首帧因版本不符被明确拒绝，必须同时升级服务端与客户端。

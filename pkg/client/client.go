package client

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"opnet/pkg/protocol"
)

// authRequest 认证请求载荷
type authRequest struct {
	Token   string `json:"token"`
	NetPort int    `json:"net_port"`
	// WantPort 非 0 时申请固定映射端口，服务端占用则拒绝
	WantPort int `json:"want_port,omitempty"`
}

// authResponse 认证响应载荷
type authResponse struct {
	OK           bool   `json:"ok"`
	AssignedPort int    `json:"assigned_port,omitempty"`
	Magic        uint16 `json:"magic"`
	ClientID     uint32 `json:"client_id,omitempty"`
	Message      string `json:"message,omitempty"`
}

// Client 端口穿透客户端
type Client struct {
	token       string
	serverAddr  string
	netPort     int
	wantPort    int
	controlPort int
	persist     bool
	timeout     time.Duration

	controlConn net.Conn
	magic       uint16
	clientID    uint32
	done        chan struct{}
	doneOnce    sync.Once
	wg          sync.WaitGroup
}

// NewClient 创建新的客户端实例
// wantPort 非 0 时向服务端申请固定映射端口
func NewClient(token string, serverAddr string, netPort int, wantPort int, controlPort int, persist bool, timeoutHours int) *Client {
	timeout := time.Duration(timeoutHours) * time.Hour
	if persist {
		// 持久化模式：非常长的超时
		timeout = 100 * 365 * 24 * time.Hour
	}

	return &Client{
		token:       token,
		serverAddr:  serverAddr,
		netPort:     netPort,
		wantPort:    wantPort,
		controlPort: controlPort,
		persist:     persist,
		timeout:     timeout,
		done:        make(chan struct{}),
	}
}

// closeDone 幂等关闭 done
// NOTE: timeoutWatcher 与 handleControlMessages 可能同时收尾，
// 直接 close 会 panic: close of closed channel，故用 sync.Once 收敛
func (c *Client) closeDone() {
	c.doneOnce.Do(func() {
		close(c.done)
	})
}

// Run 启动客户端，连接服务端并开始端口映射
func (c *Client) Run() error {
	log.Printf("[客户端] 正在连接服务端 %s:%d ...", c.serverAddr, c.controlPort)

	controlConn, err := tls.Dial("tcp",
		fmt.Sprintf("%s:%d", c.serverAddr, c.controlPort),
		protocol.ClientTLSConfig(),
	)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	c.controlConn = controlConn

	if err := c.authenticate(); err != nil {
		controlConn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}

	log.Printf("[客户端] 认证成功！")
	if !c.persist {
		log.Printf("[客户端] 超时时间: %v 后自动断开", c.timeout)
	} else {
		log.Printf("[客户端] 持久化模式已启用，不会自动断开")
	}

	// 启动心跳
	c.wg.Add(1)
	go c.heartbeatLoop()

	// 超时控制
	if !c.persist {
		go c.timeoutWatcher()
	}

	// 处理控制通道消息（阻塞直到断开）
	c.handleControlMessages()

	c.wg.Wait()
	log.Printf("[客户端] 已断开连接")
	return nil
}

// authenticate 执行 Token 认证
func (c *Client) authenticate() error {
	req := authRequest{
		Token:    c.token,
		NetPort:  c.netPort,
		WantPort: c.wantPort,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal auth request: %w", err)
	}

	// NOTE: 首次认证帧 magic=0，服务端在响应中返回协商后的 magic
	if err := protocol.WriteFrame(c.controlConn, 0, &protocol.Frame{
		Type: protocol.MsgAuth,
		Data: data,
	}); err != nil {
		return fmt.Errorf("send auth request: %w", err)
	}

	c.controlConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	frame, err := protocol.ReadFrame(c.controlConn)
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	c.controlConn.SetReadDeadline(time.Time{})

	if frame.Type != protocol.MsgAuthResp {
		return fmt.Errorf("unexpected response type: %d", frame.Type)
	}

	var resp authResponse
	if err := json.Unmarshal(frame.Data, &resp); err != nil {
		return fmt.Errorf("unmarshal auth response: %w", err)
	}

	if !resp.OK {
		return fmt.Errorf("server rejected: %s", resp.Message)
	}

	// NOTE: 认证响应必须携带本次会话 magic，否则可能存在中间人注入
	if frame.Magic != resp.Magic {
		return fmt.Errorf("magic mismatch in auth response: frame=0x%04x body=0x%04x", frame.Magic, resp.Magic)
	}

	c.magic = resp.Magic
	c.clientID = resp.ClientID
	if c.wantPort != 0 && resp.AssignedPort != c.wantPort {
		return fmt.Errorf("服务端返回的端口 %d 与申请的 %d 不一致", resp.AssignedPort, c.wantPort)
	}
	log.Printf("[客户端] 本地端口 %d → 服务端映射端口 %d (客户端 ID: %d)",
		c.netPort, resp.AssignedPort, c.clientID)

	return nil
}

// heartbeatLoop 随机间隔心跳，防止流量分析识别定时特征
func (c *Client) heartbeatLoop() {
	defer c.wg.Done()

	for {
		// 30-60 秒随机间隔
		interval := 30 + rand.Intn(31)
		select {
		case <-time.After(time.Duration(interval) * time.Second):
			if err := protocol.WriteFrame(c.controlConn, c.magic, &protocol.Frame{
				Type: protocol.MsgHeartbeat,
			}); err != nil {
				log.Printf("[客户端] 发送心跳失败: %v", err)
				return
			}
		case <-c.done:
			return
		}
	}
}

// timeoutWatcher 超时后自动断开
func (c *Client) timeoutWatcher() {
	select {
	case <-time.After(c.timeout):
		log.Printf("[客户端] 已超时（%v），正在断开连接...", c.timeout)
		protocol.WriteFrame(c.controlConn, c.magic, &protocol.Frame{
			Type: protocol.MsgDisconnect,
		})
		c.closeDone()
		c.controlConn.Close()
	case <-c.done:
		return
	}
}

// handleControlMessages 监听控制通道消息并处理
func (c *Client) handleControlMessages() {
	defer func() {
		c.closeDone()
		c.controlConn.Close()
	}()

	for {
		frame, err := protocol.ReadFrame(c.controlConn)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				log.Printf("[客户端] 读取控制消息失败: %v", err)
				return
			}
		}

		// NOTE: 校验服务端下发的会话 magic，丢弃不符合本会话的帧
		if frame.Magic != c.magic {
			log.Printf("[客户端] 控制消息 magic 校验失败 (0x%04x)，断开连接", frame.Magic)
			return
		}

		switch frame.Type {
		case protocol.MsgNewProxy:
			connID := frame.ConnID
			log.Printf("[客户端] 收到新代理请求，连接 ID: %d", connID)
			go c.openDataChannel(connID)

		case protocol.MsgHeartbeatAck:
			// 心跳回复，无需处理

		case protocol.MsgDisconnect:
			log.Printf("[客户端] 服务端要求断开连接")
			return

		default:
			log.Printf("[客户端] 未知消息类型: %d", frame.Type)
		}
	}
}

// openDataChannel 建立数据通道，将服务端外部连接转发到本地端口
func (c *Client) openDataChannel(connID uint32) {
	// 通过 TLS 连接服务端控制端口建立数据通道（独立 TCP 连接）
	dataConn, err := tls.Dial("tcp",
		fmt.Sprintf("%s:%d", c.serverAddr, c.controlPort),
		protocol.ClientTLSConfig(),
	)
	if err != nil {
		log.Printf("[客户端] 建立数据通道失败: %v", err)
		return
	}

	// 发送 NewConn 帧，携带 connID 和 clientID，以及证明持有 token 的 HMAC 标签
	// NOTE: 服务端据此校验数据通道身份，未认证连接无法接入映射端口
	payload := make([]byte, protocol.NewConnPayloadSize)
	binary.BigEndian.PutUint32(payload[0:protocol.NewConnClientIDSize], c.clientID)
	copy(payload[protocol.NewConnClientIDSize:], protocol.NewConnAuthTag(c.token, c.magic, c.clientID, connID))

	if err := protocol.WriteFrame(dataConn, c.magic, &protocol.Frame{
		Type:   protocol.MsgNewConn,
		ConnID: connID,
		Data:   payload,
	}); err != nil {
		log.Printf("[客户端] 发送 NewConn 失败: %v", err)
		dataConn.Close()
		return
	}

	// 连接本地服务端口
	localConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("127.0.0.1:%d", c.netPort),
		5*time.Second,
	)
	if err != nil {
		log.Printf("[客户端] 连接本地端口 %d 失败: %v", c.netPort, err)
		dataConn.Close()
		return
	}

	log.Printf("[客户端] 数据通道 #%d 已建立: 服务端 ↔ 本地端口 %d", connID, c.netPort)

	// 双向数据转发
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(localConn, dataConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(dataConn, localConn)
		done <- struct{}{}
	}()

	<-done
	dataConn.Close()
	localConn.Close()
	log.Printf("[客户端] 数据通道 #%d 已关闭", connID)
}

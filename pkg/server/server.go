package server

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"opnet/pkg/protocol"
)

// AuthRequest 认证请求载荷
type AuthRequest struct {
	Token   string `json:"token"`
	NetPort int    `json:"net_port"`
}

// AuthResponse 认证响应载荷
type AuthResponse struct {
	OK           bool   `json:"ok"`
	AssignedPort int    `json:"assigned_port,omitempty"`
	Magic        uint16 `json:"magic"`
	ClientID     uint32 `json:"client_id,omitempty"`
	Message      string `json:"message,omitempty"`
}

// clientSession 表示一个已连接的客户端会话
type clientSession struct {
	id           uint32
	controlConn  net.Conn
	magic        uint16
	assignedPort int
	listener     net.Listener
	// pendingConns 存储等待客户端回连的外部连接，key 为 connID
	pendingConns sync.Map
	// connMu 保护 connID 的分配与登记，保证随机 ID 不冲突
	connMu sync.Mutex
	done   chan struct{}
}

// Server 端口穿透服务端
type Server struct {
	Token       string
	BasePort    int
	ControlPort int
	sessions    sync.Map // map[uint32]*clientSession
	idMu        sync.Mutex
	// portInUse 跟踪已分配的端口
	portInUse sync.Map // map[int]bool
}

// NewServer 创建新的服务端实例
func NewServer(token string, basePort int, controlPort int) *Server {
	return &Server{
		Token:       token,
		BasePort:    basePort,
		ControlPort: controlPort,
	}
}

// HandleConnection 统一连接入口：读取首帧后路由到控制通道或数据通道
// NOTE: 控制通道和数据通道共享同一个 TLS 监听端口，
// 通过首帧消息类型区分：MsgAuth → 控制通道，MsgNewConn → 数据通道
func (s *Server) HandleConnection(conn net.Conn) {
	// 设置首帧读取超时
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		log.Printf("[服务端] 读取首帧失败 (%s): %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	switch frame.Type {
	case protocol.MsgAuth:
		s.handleControlConn(conn, frame)
	case protocol.MsgNewConn:
		s.handleDataConn(conn, frame)
	default:
		log.Printf("[服务端] 首帧类型非法: %d (%s)", frame.Type, conn.RemoteAddr())
		conn.Close()
	}
}

// handleControlConn 处理客户端控制通道连接（认证已在首帧读取）
func (s *Server) handleControlConn(conn net.Conn, authFrame *protocol.Frame) {
	remoteAddr := conn.RemoteAddr().String()

	var authReq AuthRequest
	if err := json.Unmarshal(authFrame.Data, &authReq); err != nil {
		log.Printf("[服务端] 解析认证请求失败 (%s): %v", remoteAddr, err)
		conn.Close()
		return
	}

	// 验证 token
	// NOTE: 常量时间比较，避免逐字节时序侧信道
	if subtle.ConstantTimeCompare([]byte(authReq.Token), []byte(s.Token)) != 1 {
		log.Printf("[服务端] Token 验证失败 (%s)", remoteAddr)
		resp := AuthResponse{OK: false, Message: "invalid token"}
		data, _ := json.Marshal(resp)
		protocol.WriteFrame(conn, 0, &protocol.Frame{Type: protocol.MsgAuthResp, Data: data})
		conn.Close()
		return
	}

	// 分配映射端口
	assignedPort := s.allocatePort()
	if assignedPort == 0 {
		log.Printf("[服务端] 无法分配端口 (%s)", remoteAddr)
		resp := AuthResponse{OK: false, Message: "no available port"}
		data, _ := json.Marshal(resp)
		protocol.WriteFrame(conn, 0, &protocol.Frame{Type: protocol.MsgAuthResp, Data: data})
		conn.Close()
		return
	}

	// 生成 session magic
	magic, err := protocol.GenerateMagic()
	if err != nil {
		log.Printf("[服务端] 生成 magic 失败: %v", err)
		s.releasePort(assignedPort)
		conn.Close()
		return
	}

	// NOTE: clientID 必须不可预测，否则第三方可枚举会话并抢注数据通道
	session := &clientSession{
		controlConn:  conn,
		magic:        magic,
		assignedPort: assignedPort,
		done:         make(chan struct{}),
	}
	clientID, err := s.registerSession(session)
	if err != nil {
		log.Printf("[服务端] 登记会话失败 (%s): %v", remoteAddr, err)
		resp := AuthResponse{OK: false, Message: "server busy"}
		data, _ := json.Marshal(resp)
		protocol.WriteFrame(conn, 0, &protocol.Frame{Type: protocol.MsgAuthResp, Data: data})
		s.releasePort(assignedPort)
		conn.Close()
		return
	}

	// 发送认证成功响应，包含 clientID 供数据通道回连时使用
	resp := AuthResponse{
		OK:           true,
		AssignedPort: assignedPort,
		Magic:        magic,
		ClientID:     clientID,
	}
	data, _ := json.Marshal(resp)

	if err := protocol.WriteFrame(conn, magic, &protocol.Frame{
		Type: protocol.MsgAuthResp,
		Data: data,
	}); err != nil {
		log.Printf("[服务端] 发送认证响应失败: %v", err)
		conn.Close()
		s.releasePort(assignedPort)
		s.sessions.Delete(clientID)
		return
	}

	log.Printf("[服务端] 客户端 #%d 认证成功 (%s)，映射端口 %d ← 远端本地端口 %d",
		clientID, remoteAddr, assignedPort, authReq.NetPort)

	// 启动映射端口监听
	go s.runProxyListener(session)

	// 处理控制通道后续消息（心跳、断连等）
	s.handleControlMessages(session)
}

// registerSession 分配不可预测的 clientID 并登记会话
// NOTE: 分配与登记在同一临界区内完成，保证并发认证的客户端不会拿到相同 ID
func (s *Server) registerSession(session *clientSession) (uint32, error) {
	s.idMu.Lock()
	defer s.idMu.Unlock()

	for i := 0; i < 100; i++ {
		id, err := protocol.RandomUint32()
		if err != nil {
			return 0, err
		}
		if _, loaded := s.sessions.Load(id); loaded {
			continue
		}
		session.id = id
		s.sessions.Store(id, session)
		return id, nil
	}
	return 0, fmt.Errorf("no available client id")
}

// allocatePort 分配一个可用的映射端口（从 basePort 开始递增）
func (s *Server) allocatePort() int {
	for port := s.BasePort; port < s.BasePort+100; port++ {
		if _, loaded := s.portInUse.LoadOrStore(port, true); !loaded {
			return port
		}
	}
	return 0
}

// releasePort 释放映射端口
func (s *Server) releasePort(port int) {
	s.portInUse.Delete(port)
}

// runProxyListener 在分配的映射端口上监听外部连接
func (s *Server) runProxyListener(session *clientSession) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", session.assignedPort))
	if err != nil {
		log.Printf("[服务端] 监听映射端口 %d 失败: %v", session.assignedPort, err)
		return
	}
	session.listener = listener

	log.Printf("[服务端] 映射端口 %d 已开放，等待外部连接...", session.assignedPort)

	go func() {
		<-session.done
		listener.Close()
	}()

	for {
		extConn, err := listener.Accept()
		if err != nil {
			select {
			case <-session.done:
				return
			default:
				log.Printf("[服务端] 映射端口 %d 接受连接错误: %v", session.assignedPort, err)
				continue
			}
		}

		// NOTE: connID 随机而非递增，避免第三方预测后抢注数据通道
		connID, err := session.newConnID()
		if err != nil {
			log.Printf("[服务端] 生成 connID 失败: %v", err)
			extConn.Close()
			continue
		}

		log.Printf("[服务端] 映射端口 %d 收到外部连接 #%d 来自 %s",
			session.assignedPort, connID, extConn.RemoteAddr())

		// 保存外部连接，等待客户端回连
		session.pendingConns.Store(connID, extConn)

		// 通过控制通道通知客户端建立数据通道
		if err := protocol.WriteFrame(session.controlConn, session.magic, &protocol.Frame{
			Type:   protocol.MsgNewProxy,
			ConnID: connID,
		}); err != nil {
			log.Printf("[服务端] 发送 NewProxy 通知失败: %v", err)
			extConn.Close()
			session.pendingConns.Delete(connID)
		}
	}
}

// newConnID 生成会话内唯一的随机 connID
func (cs *clientSession) newConnID() (uint32, error) {
	cs.connMu.Lock()
	defer cs.connMu.Unlock()

	for i := 0; i < 100; i++ {
		id, err := protocol.RandomUint32()
		if err != nil {
			return 0, err
		}
		if _, loaded := cs.pendingConns.Load(id); loaded {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("no available conn id")
}

// handleControlMessages 处理控制通道中的持续消息（心跳、断连等）
func (s *Server) handleControlMessages(session *clientSession) {
	defer func() {
		log.Printf("[服务端] 客户端 #%d 断开连接，释放端口 %d", session.id, session.assignedPort)
		close(session.done)
		session.controlConn.Close()
		s.releasePort(session.assignedPort)
		s.sessions.Delete(session.id)

		// 关闭所有未完成的外部连接
		session.pendingConns.Range(func(key, value any) bool {
			if conn, ok := value.(net.Conn); ok {
				conn.Close()
			}
			session.pendingConns.Delete(key)
			return true
		})
	}()

	for {
		frame, err := protocol.ReadFrame(session.controlConn)
		if err != nil {
			log.Printf("[服务端] 读取控制消息失败 (客户端 #%d): %v", session.id, err)
			return
		}

		// NOTE: 控制通道帧必须携带会话 magic（认证首帧除外，那时 magic 还没下发）
		if frame.Magic != session.magic {
			log.Printf("[服务端] 控制消息 magic 校验失败 (客户端 #%d): 0x%04x", session.id, frame.Magic)
			return
		}

		switch frame.Type {
		case protocol.MsgHeartbeat:
			// 回复心跳
			protocol.WriteFrame(session.controlConn, session.magic, &protocol.Frame{
				Type: protocol.MsgHeartbeatAck,
			})

		case protocol.MsgDisconnect:
			log.Printf("[服务端] 客户端 #%d 主动断开", session.id)
			return

		default:
			log.Printf("[服务端] 未知消息类型: %d (客户端 #%d)", frame.Type, session.id)
		}
	}
}

// handleDataConn 处理来自客户端的数据通道回连
// NOTE: 客户端收到 NewProxy 后，主动连接控制端口发送 MsgNewConn 帧，
// 服务端校验会话 magic 与 HMAC 后再匹配 connID，将数据通道与对应的外部连接双向转发。
// 校验必须先于消费 pendingConns，否则攻击者可用伪造帧把等待中的外部连接"烧掉"(DoS)。
func (s *Server) handleDataConn(conn net.Conn, frame *protocol.Frame) {
	// 载荷 = ClientID(4) | AuthTag(16)
	if len(frame.Data) < protocol.NewConnPayloadSize {
		log.Printf("[服务端] 数据通道认证失败: 载荷长度非法 %d (%s)", len(frame.Data), conn.RemoteAddr())
		conn.Close()
		return
	}

	clientID := binary.BigEndian.Uint32(frame.Data[0:protocol.NewConnClientIDSize])
	tag := frame.Data[protocol.NewConnClientIDSize:protocol.NewConnPayloadSize]

	// 查找对应的 session
	sessionVal, ok := s.sessions.Load(clientID)
	if !ok {
		log.Printf("[服务端] 数据通道认证失败: 未知客户端 #%d (%s)", clientID, conn.RemoteAddr())
		conn.Close()
		return
	}
	session := sessionVal.(*clientSession)

	// NOTE: 这是修复未认证劫持的关键校验——数据通道与首帧认证无关，
	// 必须证明持有 token（HMAC 以 token 为密钥），并校验会话 magic。
	if frame.Magic != session.magic ||
		!protocol.VerifyNewConnAuth(s.Token, session.magic, clientID, frame.ConnID, tag) {
		log.Printf("[服务端] 数据通道认证失败: magic/HMAC 校验不通过 (客户端 #%d, conn #%d, %s)",
			clientID, frame.ConnID, conn.RemoteAddr())
		conn.Close()
		return
	}

	// 认证通过后才消费等待中的外部连接
	extConnVal, ok := session.pendingConns.LoadAndDelete(frame.ConnID)
	if !ok {
		log.Printf("[服务端] 数据通道: 找不到等待连接 #%d", frame.ConnID)
		conn.Close()
		return
	}
	extConn := extConnVal.(net.Conn)

	log.Printf("[服务端] 数据通道 #%d 已建立 (客户端 #%d)，开始双向转发", frame.ConnID, clientID)

	// 双向数据转发
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(extConn, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, extConn)
		done <- struct{}{}
	}()

	// 任一方向关闭则结束
	<-done
	conn.Close()
	extConn.Close()
	log.Printf("[服务端] 数据通道 #%d 已关闭", frame.ConnID)
}

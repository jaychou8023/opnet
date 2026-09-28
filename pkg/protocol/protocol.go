package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

// NOTE: 自定义二进制帧协议，避免使用已知穿透工具的协议特征
// 帧结构: Magic(2) + Ver(1) + Type(1) + ConnID(4) + Len(4) + Payload(variable)
//
// v2 变更: MsgNewConn 载荷由裸 ClientID 改为 ClientID(4) + AuthTag(16)，
// 数据通道必须通过 HMAC 证明持有 token；同时 clientID/connID 改为随机值。
// 旧版客户端会在首帧因版本不符被明确拒绝，避免"认证成功但数据通道静默失败"。
const (
	frameHeaderSize = 12 // 2 + 1 + 1 + 4 + 4
	protocolVersion = 0x02
	maxPayloadSize  = 1 << 20 // 1MB 防止异常大包
)

// MsgNewConn 载荷布局
// NOTE: 数据通道与控制通道共用同一监听端口，首帧类型无法证明身份，
// 因此必须用 token 作为密钥做 HMAC，否则任何能连上控制端口的人
// 都可以抢注 connID 劫持他人映射端口上的连接。
const (
	NewConnClientIDSize = 4
	NewConnAuthTagSize  = 16 // HMAC-SHA256 截断
	NewConnPayloadSize  = NewConnClientIDSize + NewConnAuthTagSize
)

// 消息类型常量
const (
	MsgAuth         uint8 = 0x01
	MsgAuthResp     uint8 = 0x02
	MsgNewProxy     uint8 = 0x03
	MsgNewConn      uint8 = 0x04
	MsgHeartbeat    uint8 = 0x05
	MsgHeartbeatAck uint8 = 0x06
	MsgDisconnect   uint8 = 0x07
)

// Frame 表示一个协议帧
type Frame struct {
	Magic  uint16
	Type   uint8
	ConnID uint32
	Data   []byte
}

// WriteFrame 将帧编码并写入连接
func WriteFrame(conn net.Conn, magic uint16, f *Frame) error {
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], magic)
	header[2] = protocolVersion
	header[3] = f.Type
	binary.BigEndian.PutUint32(header[4:8], f.ConnID)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(f.Data)))

	// NOTE: 先写 header 再写 payload，避免一次性分配大内存
	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(f.Data) > 0 {
		if _, err := conn.Write(f.Data); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}
	return nil
}

// ReadFrame 从连接中读取并解码一个帧
func ReadFrame(conn net.Conn) (*Frame, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}

	magic := binary.BigEndian.Uint16(header[0:2])
	ver := header[2]
	if ver != protocolVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d", ver)
	}

	msgType := header[3]
	connID := binary.BigEndian.Uint32(header[4:8])
	payloadLen := binary.BigEndian.Uint32(header[8:12])

	if payloadLen > uint32(maxPayloadSize) {
		return nil, fmt.Errorf("payload too large: %d", payloadLen)
	}

	var data []byte
	if payloadLen > 0 {
		data = make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, data); err != nil {
			return nil, fmt.Errorf("read frame payload: %w", err)
		}
	}

	return &Frame{
		Magic:  magic,
		Type:   msgType,
		ConnID: connID,
		Data:   data,
	}, nil
}

// GenerateMagic 生成随机的 2 字节 session magic
func GenerateMagic() (uint16, error) {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// RandomUint32 生成非零随机 uint32，用于不可预测的 clientID / connID
// NOTE: 原来这两个 ID 从 1 递增，攻击者可精确猜中并抢注
func RandomUint32() (uint32, error) {
	b := make([]byte, 4)
	for i := 0; i < 64; i++ {
		if _, err := rand.Read(b); err != nil {
			return 0, fmt.Errorf("read random: %w", err)
		}
		if v := binary.BigEndian.Uint32(b); v != 0 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("generate random uint32 failed")
}

// NewConnAuthTag 计算数据通道认证标签
// NOTE: 以 token 为密钥对 session magic + clientID + connID 做 HMAC-SHA256 并截断。
// magic 由服务端在认证响应中经 TLS 下发，token 只有双方知道，
// 二者共同保证数据通道确实来自已认证的客户端。
func NewConnAuthTag(token string, magic uint16, clientID, connID uint32) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	var buf [10]byte
	binary.BigEndian.PutUint16(buf[0:2], magic)
	binary.BigEndian.PutUint32(buf[2:6], clientID)
	binary.BigEndian.PutUint32(buf[6:10], connID)
	mac.Write(buf[:])
	return mac.Sum(nil)[:NewConnAuthTagSize]
}

// VerifyNewConnAuth 校验数据通道认证标签（常量时间比较）
func VerifyNewConnAuth(token string, magic uint16, clientID, connID uint32, tag []byte) bool {
	if len(tag) != NewConnAuthTagSize {
		return false
	}
	expected := NewConnAuthTag(token, magic, clientID, connID)
	return hmac.Equal(expected, tag)
}

// GenerateTLSConfig 生成自签名 TLS 配置用于控制通道加密
// NOTE: 使用 ECDSA P-256 密钥，TLS 1.3 only，外观与普通 HTTPS 流量一致
func GenerateTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	// 证书有效期 1 年，使用通用域名避免引起注意
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CloudFlare Inc"},
			CommonName:   "cloudflare-dns.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"cloudflare-dns.com", "*.cloudflare-dns.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig 返回客户端 TLS 配置（跳过证书验证，因为使用自签名证书）
func ClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
}

package protocol

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// pipeConns 返回一对已连接的内存管道，模拟 net.Conn
func pipeConns() (net.Conn, net.Conn) {
	return net.Pipe()
}

func TestFrameRoundTrip(t *testing.T) {
	client, server := pipeConns()
	defer client.Close()
	defer server.Close()

	want := &Frame{Type: MsgNewProxy, ConnID: 0xDEADBEEF, Data: []byte("hello opnet")}

	go func() {
		if err := WriteFrame(client, 0x1234, want); err != nil {
			t.Errorf("WriteFrame: %v", err)
		}
	}()

	got, err := ReadFrame(server)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Magic != 0x1234 {
		t.Errorf("magic = 0x%04x, want 0x1234", got.Magic)
	}
	if got.Type != want.Type {
		t.Errorf("type = %d, want %d", got.Type, want.Type)
	}
	if got.ConnID != want.ConnID {
		t.Errorf("connID = %d, want %d", got.ConnID, want.ConnID)
	}
	if !bytes.Equal(got.Data, want.Data) {
		t.Errorf("data = %q, want %q", got.Data, want.Data)
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	client, server := pipeConns()
	defer client.Close()
	defer server.Close()

	go WriteFrame(client, 0, &Frame{Type: MsgHeartbeat})

	got, err := ReadFrame(server)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Type != MsgHeartbeat || len(got.Data) != 0 {
		t.Errorf("got type=%d data=%q, want heartbeat with empty payload", got.Type, got.Data)
	}
}

func TestReadFrameRejectsWrongVersion(t *testing.T) {
	client, server := pipeConns()
	defer client.Close()
	defer server.Close()

	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], 0x1234)
	header[2] = protocolVersion + 1 // 伪造未来版本
	header[3] = MsgAuth
	go client.Write(header)

	if _, err := ReadFrame(server); err == nil {
		t.Fatal("期望版本不符被拒绝，实际通过了")
	}
}

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	client, server := pipeConns()
	defer client.Close()
	defer server.Close()

	header := make([]byte, frameHeaderSize)
	header[2] = protocolVersion
	header[3] = MsgNewConn
	binary.BigEndian.PutUint32(header[8:12], maxPayloadSize+1)
	go client.Write(header)

	if _, err := ReadFrame(server); err == nil {
		t.Fatal("期望超大载荷被拒绝，实际通过了")
	}
}

// 数据通道认证：这是修复未认证劫持的核心保证
func TestNewConnAuthTagVerification(t *testing.T) {
	const token = "opnet123"
	const magic uint16 = 0xABCD
	const clientID uint32 = 0x11223344
	const connID uint32 = 0x55667788

	tag := NewConnAuthTag(token, magic, clientID, connID)
	if len(tag) != NewConnAuthTagSize {
		t.Fatalf("tag 长度 = %d, want %d", len(tag), NewConnAuthTagSize)
	}
	if !VerifyNewConnAuth(token, magic, clientID, connID, tag) {
		t.Fatal("正确的标签应当校验通过")
	}

	cases := []struct {
		name     string
		token    string
		magic    uint16
		clientID uint32
		connID   uint32
		tag      []byte
	}{
		{"错误 token", "wrong-token", magic, clientID, connID, tag},
		{"错误 magic", token, magic + 1, clientID, connID, tag},
		{"错误 clientID", token, magic, clientID + 1, connID, tag},
		{"错误 connID", token, magic, clientID, connID + 1, tag},
		{"全零伪造标签", token, magic, clientID, connID, make([]byte, NewConnAuthTagSize)},
		{"截断标签", token, magic, clientID, connID, tag[:NewConnAuthTagSize-1]},
		{"空标签", token, magic, clientID, connID, nil},
	}
	for _, tc := range cases {
		if VerifyNewConnAuth(tc.token, tc.magic, tc.clientID, tc.connID, tc.tag) {
			t.Errorf("%s: 应当校验失败，实际通过", tc.name)
		}
	}
}

func TestNewConnAuthTagBindsAllFields(t *testing.T) {
	// 相同输入必须产生相同标签（可复现），不同输入必须不同（抗碰撞即可）
	a := NewConnAuthTag("t", 1, 2, 3)
	b := NewConnAuthTag("t", 1, 2, 3)
	if !bytes.Equal(a, b) {
		t.Error("相同输入应产生相同标签")
	}
	c := NewConnAuthTag("t", 1, 3, 2)
	if bytes.Equal(a, c) {
		t.Error("字段互换后标签不应相同（防止字段拼接歧义）")
	}
}

func TestRandomUint32(t *testing.T) {
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		v, err := RandomUint32()
		if err != nil {
			t.Fatalf("RandomUint32: %v", err)
		}
		if v == 0 {
			t.Fatal("不应返回 0")
		}
		seen[v] = true
	}
	if len(seen) < 95 { // 100 次里允许极少量碰撞
		t.Errorf("随机性不足: 100 次仅 %d 个不同值", len(seen))
	}
}

func TestGenerateMagicVaried(t *testing.T) {
	seen := make(map[uint16]bool)
	for i := 0; i < 50; i++ {
		m, err := GenerateMagic()
		if err != nil {
			t.Fatalf("GenerateMagic: %v", err)
		}
		seen[m] = true
	}
	if len(seen) < 20 {
		t.Errorf("magic 随机性不足: 50 次仅 %d 个不同值", len(seen))
	}
}

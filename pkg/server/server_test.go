package server

import (
	"testing"

	"opnet/pkg/protocol"
)

func TestPortCandidatesAuto(t *testing.T) {
	ports, err := portCandidates(2222, 0)
	if err != nil {
		t.Fatalf("portCandidates(auto): %v", err)
	}
	if len(ports) != protocol.PortSlots {
		t.Fatalf("候选端口数 = %d, want %d", len(ports), protocol.PortSlots)
	}
	if ports[0] != 2222 || ports[len(ports)-1] != 2222+protocol.PortSlots-1 {
		t.Errorf("范围 = %d..%d, want 2222..%d", ports[0], ports[len(ports)-1], 2222+protocol.PortSlots-1)
	}
}

func TestPortCandidatesFixed(t *testing.T) {
	// 申请固定端口时只应返回它自己，即"占用就报错、不换端口"
	ports, err := portCandidates(2222, 2223)
	if err != nil {
		t.Fatalf("portCandidates(fixed): %v", err)
	}
	if len(ports) != 1 || ports[0] != 2223 {
		t.Fatalf("候选端口 = %v, want [2223]", ports)
	}
}

func TestPortCandidatesOutOfRange(t *testing.T) {
	base := 2222
	cases := []int{base - 1, base + protocol.PortSlots, 0 - 1, 1, 65535}
	for _, want := range cases {
		if _, err := portCandidates(base, want); err == nil {
			t.Errorf("wantPort=%d 越界，应当报错", want)
		}
	}
	// 边界内的首尾必须被接受
	for _, want := range []int{base, base + protocol.PortSlots - 1} {
		ports, err := portCandidates(base, want)
		if err != nil {
			t.Errorf("wantPort=%d 在范围内，不应报错: %v", want, err)
		}
		if len(ports) != 1 || ports[0] != want {
			t.Errorf("wantPort=%d 候选 = %v", want, ports)
		}
	}
}

// 真实 listen 的端到端校验：占用应报错、释放后可再次占用
func TestListenPortFixedAndBusy(t *testing.T) {
	const base = 45300
	srv := NewServer("t", base, 2221)

	ln, port, err := srv.listenPort(base)
	if err != nil {
		t.Fatalf("首次 listenPort(%d): %v", base, err)
	}
	if port != base {
		t.Fatalf("port = %d, want %d", port, base)
	}

	// 同一端口再次申请必须失败（不静默换端口）
	if _, _, err := srv.listenPort(base); err == nil {
		t.Error("端口已被占用，第二次申请应当报错")
	} else {
		t.Logf("占用报错符合预期: %v", err)
	}

	// 自动分配应跳过已占用端口
	_, autoPort, err := srv.listenPort(0)
	if err != nil {
		t.Fatalf("自动分配失败: %v", err)
	}
	if autoPort == base {
		t.Errorf("自动分配不应再次给出已占用的 %d", base)
	}

	ln.Close()
	srv.releasePort(base)
	if _, _, err := srv.listenPort(base); err != nil {
		t.Errorf("释放后应可再次申请 %d: %v", base, err)
	}
}

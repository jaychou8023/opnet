package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"

	"opnet/pkg/protocol"
	"opnet/pkg/server"
)

func main() {
	token := flag.String("token", "", "认证 Token（必填）")
	port := flag.Int("port", 2222, "基础映射端口")
	controlPort := flag.Int("cport", 2221, "控制通道端口")
	flag.Parse()

	if *token == "" {
		log.Fatal("[服务端] 错误: 必须指定 -token 参数")
	}

	fmt.Println("========================================")
	fmt.Println("  OpNet 端口穿透服务端")
	fmt.Println("========================================")
	fmt.Printf("  控制端口: %d\n", *controlPort)
	fmt.Printf("  基础映射端口: %d\n", *port)
	fmt.Println("  等待客户端连接...")
	fmt.Println("========================================")

	srv := server.NewServer(*token, *port, *controlPort)

	// 生成 TLS 配置并启动 TLS 监听
	tlsCfg, err := protocol.GenerateTLSConfig()
	if err != nil {
		log.Fatalf("[服务端] 生成 TLS 配置失败: %v", err)
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", *controlPort), tlsCfg)
	if err != nil {
		log.Fatalf("[服务端] 监听控制端口 %d 失败: %v", *controlPort, err)
	}
	defer listener.Close()

	log.Printf("[服务端] 已就绪，等待客户端连接...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[服务端] 接受连接错误: %v", err)
			continue
		}
		// NOTE: 每个连接在独立 goroutine 中处理，根据首帧类型路由
		go srv.HandleConnection(conn)
	}
}

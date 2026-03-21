package main

import (
	"flag"
	"fmt"
	"log"

	"opnet/pkg/client"
)

func main() {
	token := flag.String("token", "", "认证 Token（必填）")
	serverAddr := flag.String("server", "", "服务端地址（域名或 IP，必填）")
	netPort := flag.Int("netport", 0, "要映射的本地端口（必填，如 22）")
	controlPort := flag.Int("port", 2221, "服务端控制通道端口（默认 2221）")
	persist := flag.Bool("persist", false, "持久化模式，不自动断开")
	timeout := flag.Int("timeout", 2, "超时时间（小时），默认 2 小时后自动断开")
	flag.Parse()

	if *token == "" {
		log.Fatal("[客户端] 错误: 必须指定 -token 参数")
	}
	if *serverAddr == "" {
		log.Fatal("[客户端] 错误: 必须指定 -server 参数（服务端地址）")
	}
	if *netPort == 0 {
		log.Fatal("[客户端] 错误: 必须指定 -netport 参数（本地端口）")
	}

	fmt.Println("========================================")
	fmt.Println("  OpNet 端口穿透客户端")
	fmt.Println("========================================")
	fmt.Printf("  服务端: %s:%d\n", *serverAddr, *controlPort)
	fmt.Printf("  本地端口: %d\n", *netPort)
	if *persist {
		fmt.Println("  模式: 持久化（不自动断开）")
	} else {
		fmt.Printf("  模式: 定时（%d 小时后自动断开）\n", *timeout)
	}
	fmt.Println("========================================")

	c := client.NewClient(*token, *serverAddr, *netPort, *controlPort, *persist, *timeout)

	if err := c.Run(); err != nil {
		log.Fatalf("[客户端] 运行错误: %v", err)
	}
}

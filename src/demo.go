package main

import (
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "time"
)

type Server struct {
    addr     string
    password string
    cert     tls.Certificate
}

func NewServer(addr, password, certFile, keyFile string) (*Server, error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }

    return &Server{
        addr:     addr,
        password: password,
        cert:     cert,
    }, nil
}

func (s *Server) Run() error {
    // TLS 配置
    config := &tls.Config{
        Certificates: []tls.Certificate{s.cert},
    }

    // 监听 TLS 连接
    listener, err := tls.Listen("tcp", s.addr, config)
    if err != nil {
        return err
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }

        go s.handleConnection(conn)
    }
}

func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()

    // 设置超时
    conn.SetDeadline(time.Now().Add(10 * time.Second))

    // 验证密码
    buf := make([]byte, 256)
    n, err := conn.Read(buf)
    if err != nil || string(buf[:n]) != s.password {
        return
    }

    // 读取目标地址
    n, err = conn.Read(buf)
    if err != nil {
        return
    }
    targetAddr := string(buf[:n])

    // 连接目标服务器
    target, err := net.Dial("tcp", targetAddr)
    if err != nil {
        return
    }
    defer target.Close()

    // 双向转发数据
    go func() {
        io.Copy(target, conn)
    }()
    io.Copy(conn, target)
}

func main() {
    server, err := NewServer(":443", "your-password", "cert.pem", "key.pem")
    if err != nil {
        fmt.Printf("Failed to create server: %v\n", err)
        return
    }

    fmt.Println("Server running...")
    if err := server.Run(); err != nil {
        fmt.Printf("Server error: %v\n", err)
    }
}
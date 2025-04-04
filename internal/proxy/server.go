package proxy

import (
    "fmt"
    "net"
)

type ProxyServer struct {
    connections chan net.Conn
    errors      chan error
}

func NewProxyServer() *ProxyServer {
    return &ProxyServer{
        connections: make(chan net.Conn),
        errors:      make(chan error),
    }
}

func (s *ProxyServer) Initialize(port string) error {
    networkListener, err := s.createListener(port)
    if err != nil {
        return err
    }
    defer networkListener.Close()
    return s.processConnections(networkListener)
}

func (s *ProxyServer) createListener(port string) (net.Listener, error) {
    return net.Listen("tcp", fmt.Sprintf(":%s", port))
}

func (s *ProxyServer) processConnections(listener net.Listener) error {
    for {
        incomingConn, err := listener.Accept()
        if err != nil {
            continue
        }
        go NewConnectionHandler(incomingConn).ProcessRequest()
    }
}

type ProxyListener struct {
    port     string
    listener net.Listener
    done     chan struct{}
}

func NewProxyListener(port string) *ProxyListener {
    return &ProxyListener{
        port: port,
        done: make(chan struct{}),
    }
}

func StartProxy(port string) error {
    proxyListener := NewProxyListener(port)
    return proxyListener.serve()
}

func (p *ProxyListener) serve() error {
    if err := p.initializeListener(); err != nil {
        return fmt.Errorf("ошибка инициализации сервера: %w", err)
    }
    defer p.listener.Close()

    fmt.Printf("MITM-прокси запущен на порту %s\n", p.port)
    return p.acceptConnections()
}

func (p *ProxyListener) initializeListener() error {
    networkAddr := fmt.Sprintf(":%s", p.port)
    listener, err := net.Listen("tcp", networkAddr)
    if err != nil {
        return fmt.Errorf("не удалось создать слушателя: %w", err)
    }
    p.listener = listener
    return nil
}

func (p *ProxyListener) acceptConnections() error {
    for {
        select {
        case <-p.done:
            return nil
        default:
            if err := p.acceptSingleConnection(); err != nil {
                fmt.Printf("Предупреждение при обработке соединения: %v\n", err)
            }
        }
    }
}

func (p *ProxyListener) acceptSingleConnection() error {
    conn, err := p.listener.Accept()
    if err != nil {
        return fmt.Errorf("ошибка при принятии соединения: %w", err)
    }
    
    go handleClient(conn)
    return nil
}

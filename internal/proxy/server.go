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

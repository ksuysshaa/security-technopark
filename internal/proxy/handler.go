package proxy

import (
    "bufio"
    "fmt"
    "io"
    "net"
    "net/url"
    "strings"
    "time"
)

type ConnectionHandler struct {
    clientConnection net.Conn
    requestData      *RequestData
}

type RequestData struct {
    method      string
    targetURL   string
    httpVersion string
    headers     []HeaderLine
    body        []byte
}

type HeaderLine struct {
    name  string
    value string
}

func NewConnectionHandler(conn net.Conn) *ConnectionHandler {
    return &ConnectionHandler{
        clientConnection: conn,
        requestData:      &RequestData{},
    }
}

func (h *ConnectionHandler) ProcessRequest() {
    defer h.clientConnection.Close()

    if err := h.parseIncomingRequest(); err != nil {
        return
    }

    if err := h.forwardToDestination(); err != nil {
        return
    }
}

func (h *ConnectionHandler) parseIncomingRequest() error {
    reader := bufio.NewReader(h.clientConnection)
    
    if err := h.readRequestLine(reader); err != nil {
        return err
    }

    if err := h.parseHeaders(reader); err != nil {
        return err
    }

    if err := h.readRequestBody(reader); err != nil {
        return err
    }

    return nil
}

func (h *ConnectionHandler) readRequestLine(reader *bufio.Reader) error {
    line, err := reader.ReadString('\n')
    if err != nil {
        return err
    }

    parts := strings.Fields(strings.TrimSpace(line))
    if len(parts) != 3 {
        return fmt.Errorf("некорректный формат запроса")
    }

    h.requestData.method = parts[0]
    h.requestData.targetURL = parts[1]
    h.requestData.httpVersion = parts[2]
    return nil
}

func (h *ConnectionHandler) parseHeaders(reader *bufio.Reader) error {
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            return err
        }

        line = strings.TrimSpace(line)
        if line == "" {
            break
        }

        if header := h.parseHeaderLine(line); header != nil {
            h.requestData.headers = append(h.requestData.headers, *header)
        }
    }
    return nil
}

func (h *ConnectionHandler) parseHeaderLine(line string) *HeaderLine {
    parts := strings.SplitN(line, ":", 2)
    if len(parts) != 2 {
        return nil
    }

    name := strings.TrimSpace(parts[0])
    value := strings.TrimSpace(parts[1])
    
    if strings.ToLower(name) == "proxy-connection" {
        return nil
    }

    return &HeaderLine{name: name, value: value}
}

func (h *ConnectionHandler) readRequestBody(reader *bufio.Reader) error {
    if h.requestData.method == "GET" || h.requestData.method == "HEAD" {
        return nil
    }

    h.clientConnection.SetReadDeadline(time.Now().Add(5 * time.Second))
    defer h.clientConnection.SetReadDeadline(time.Time{})

    buffer := make([]byte, 8192)
    for {
        n, err := reader.Read(buffer)
        if n > 0 {
            h.requestData.body = append(h.requestData.body, buffer[:n]...)
        }
        if err != nil {
            if err == io.EOF {
                return nil
            }
            return err
        }
    }
}

func (h *ConnectionHandler) forwardToDestination() error {
    targetURL, err := url.Parse(h.requestData.targetURL)
    if err != nil {
        return err
    }

    destConn, err := h.establishConnection(targetURL)
    if err != nil {
        return err
    }
    defer destConn.Close()

    if err := h.sendRequest(destConn, targetURL); err != nil {
        return err
    }

    return h.relayResponse(destConn)
}

func (h *ConnectionHandler) establishConnection(targetURL *url.URL) (net.Conn, error) {
    host := targetURL.Hostname()
    port := targetURL.Port()
    if port == "" {
        port = "80"
    }

    return net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
}

func (h *ConnectionHandler) sendRequest(dest net.Conn, targetURL *url.URL) error {
    requestBuilder := strings.Builder{}
    
    requestBuilder.WriteString(fmt.Sprintf("%s / %s\r\n", 
        h.requestData.method, h.requestData.httpVersion))

    for _, header := range h.requestData.headers {
        requestBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", 
            header.name, header.value))
    }
    
    if !h.hasHeader("Host") {
        requestBuilder.WriteString(fmt.Sprintf("Host: %s\r\n", targetURL.Host))
    }

    requestBuilder.WriteString("\r\n")

    if _, err := dest.Write([]byte(requestBuilder.String())); err != nil {
        return err
    }

    if len(h.requestData.body) > 0 {
        if _, err := dest.Write(h.requestData.body); err != nil {
            return err
        }
    }

    return nil
}

func (h *ConnectionHandler) hasHeader(name string) bool {
    lowerName := strings.ToLower(name)
    for _, header := range h.requestData.headers {
        if strings.ToLower(header.name) == lowerName {
            return true
        }
    }
    return false
}

func (h *ConnectionHandler) relayResponse(src net.Conn) error {
    buffer := make([]byte, 8192)
    for {
        src.SetReadDeadline(time.Now().Add(5 * time.Second))
        n, err := src.Read(buffer)
        if n > 0 {
            if _, err := h.clientConnection.Write(buffer[:n]); err != nil {
                return err
            }
        }
        if err == io.EOF {
            return nil
        }
        if err != nil {
            return err
        }
    }
}

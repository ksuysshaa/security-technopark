package proxy

import (
    "bufio"
    "fmt"
    "io"
    "net"
    "net/url"
    "strings"
    "time"
    "crypto/tls"
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

type RequestProcessor struct {
    clientConn     net.Conn
    reader         *bufio.Reader
    requestMethod  string
    requestTarget  string
    protocolVer    string
    requestHeaders []HeaderField
    requestBody    []byte
}

type HeaderField struct {
    key   string
    value string
}

type TLSConnectionManager struct {
    clientConn net.Conn
    serverName string
    targetPort string
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

func handleClient(clientConn net.Conn) {
    processor := &RequestProcessor{
        clientConn: clientConn,
        reader:    bufio.NewReader(clientConn),
    }
    defer clientConn.Close()

    if err := processor.parseInitialRequest(); err != nil {
        return
    }

    if processor.isTLSConnection() {
        processor.handleSecureConnection()
    } else {
        processor.handlePlainConnection()
    }
}

func (p *RequestProcessor) parseInitialRequest() error {
    requestLine, err := p.reader.ReadString('\n')
    if err != nil || strings.TrimSpace(requestLine) == "" {
        return fmt.Errorf("невозможно прочитать запрос: %v", err)
    }

    return p.parseRequestLine(strings.TrimSpace(requestLine))
}

func (p *RequestProcessor) parseRequestLine(line string) error {
    components := strings.SplitN(line, " ", 3)
    if len(components) != 3 {
        return fmt.Errorf("некорректный формат запроса: %s", line)
    }

    p.requestMethod = components[0]
    p.requestTarget = components[1]
    p.protocolVer = components[2]
    return nil
}

func (p *RequestProcessor) isTLSConnection() bool {
    return strings.ToUpper(p.requestMethod) == "CONNECT"
}

func (p *RequestProcessor) handlePlainConnection() {
    headers := p.collectHeaders()
    targetURL, err := url.Parse(p.requestTarget)
    if err != nil {
        return
    }

    connection := &ConnectionDetails{
        host:     targetURL.Hostname(),
        port:     p.determinePort(targetURL),
        path:     p.determinePath(targetURL),
        headers:  headers,
    }

    p.forwardHTTPRequest(connection)
}

func (p *RequestProcessor) collectHeaders() map[string]string {
    headers := make(map[string]string)
    for {
        line, err := p.reader.ReadString('\n')
        if err != nil || strings.TrimSpace(line) == "" {
            break
        }
        
        if key, value := p.parseHeader(line); key != "" {
            headers[key] = value
        }
    }
    return headers
}

func (p *RequestProcessor) parseHeader(line string) (string, string) {
    parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
    if len(parts) != 2 {
        return "", ""
    }
    return strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
}

type ConnectionDetails struct {
    host    string
    port    string
    path    string
    headers map[string]string
}

func (p *RequestProcessor) forwardHTTPRequest(conn *ConnectionDetails) {
    targetConn, err := net.Dial("tcp", net.JoinHostPort(conn.host, conn.port))
    if err != nil {
        return
    }
    defer targetConn.Close()

    p.sendModifiedRequest(targetConn, conn)
    p.relayData(targetConn)
}

func (p *RequestProcessor) handleSecureConnection() {
    host, port := p.extractHostAndPort(p.requestTarget)
    
    tlsManager := &TLSConnectionManager{
        clientConn: p.clientConn,
        serverName: host,
        targetPort: port,
    }
    
    if err := tlsManager.establishTLSConnection(); err != nil {
        return
    }
}

func (p *RequestProcessor) extractHostAndPort(target string) (string, string) {
    if !strings.Contains(target, ":") {
        return target, "443"
    }
    host, port, _ := net.SplitHostPort(target)
    return host, port
}

func (t *TLSConnectionManager) establishTLSConnection() error {
    t.clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

    cert, err := getOrGenerateCert(t.serverName)
    if err != nil {
        return err
    }

    tlsConn := tls.Server(t.clientConn, &tls.Config{
        Certificates: []tls.Certificate{*cert},
        ServerName:   t.serverName,
    })
    defer tlsConn.Close()

    if err := tlsConn.Handshake(); err != nil {
        return err
    }

    return t.connectToRemoteServer(tlsConn)
}

func (t *TLSConnectionManager) connectToRemoteServer(clientTLS *tls.Conn) error {
    serverConn, err := tls.Dial("tcp", 
        net.JoinHostPort(t.serverName, t.targetPort),
        &tls.Config{InsecureSkipVerify: true})
    if err != nil {
        return err
    }
    defer serverConn.Close()

    go io.Copy(serverConn, clientTLS)
    io.Copy(clientTLS, serverConn)
    return nil
}

func (p *RequestProcessor) determinePort(targetURL *url.URL) string {
    if port := targetURL.Port(); port != "" {
        return port
    }
    if targetURL.Scheme == "https" {
        return "443"
    }
    return "80"
}

func (p *RequestProcessor) determinePath(targetURL *url.URL) string {
    if path := targetURL.RequestURI(); path != "" {
        return path
    }
    return "/"
}

func (p *RequestProcessor) sendModifiedRequest(targetConn net.Conn, conn *ConnectionDetails) error {
    requestBuilder := strings.Builder{}
    
    requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", 
        p.requestMethod, conn.path, p.protocolVer))

    for key, value := range conn.headers {
        if strings.ToLower(key) != "proxy-connection" {
            requestBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
        }
    }
    
    if _, ok := conn.headers["host"]; !ok {
        requestBuilder.WriteString(fmt.Sprintf("Host: %s\r\n", conn.host))
    }

    requestBuilder.WriteString("\r\n")

    if _, err := targetConn.Write([]byte(requestBuilder.String())); err != nil {
        return err
    }

    if len(p.requestBody) > 0 {
        if _, err := targetConn.Write(p.requestBody); err != nil {
            return err
        }
    }

    return nil
}

func (p *RequestProcessor) relayData(targetConn net.Conn) error {
    buffer := make([]byte, 8192)
    for {
        targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
        n, err := targetConn.Read(buffer)
        if n > 0 {
            if _, err := p.clientConn.Write(buffer[:n]); err != nil {
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

package main

import (
    "fmt"
    "log"
    "os"

    "security-technopark/internal/proxy"
)

func main() {
    proxyServer := proxy.NewProxyServer()
    log.Printf("Инициализация HTTP прокси сервера...")
    
    if err := proxyServer.Initialize("8080"); err != nil {
        fmt.Fprintf(os.Stderr, "Критическая ошибка при запуске: %v\n", err)
        os.Exit(1)
    }
}
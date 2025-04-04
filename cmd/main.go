package main

import (
    "fmt"
    "log"
    "os"

    "security-technopark/internal/proxy"
)

func main() {
    port := getPort()
    
    log.Printf("Запуск MITM-прокси сервера на порту %s...", port)

    if err := run(port); err != nil {
        fmt.Fprintf(os.Stderr, "Критическая ошибка: %v\n", err)
        os.Exit(1)
    }
}

func getPort() string {
    if len(os.Args) > 1 {
        return os.Args[1]
    }
    return "8080"
}

func run(port string) error {
    if err := proxy.LoadCA("ca.crt", "ca.key"); err != nil {
        return fmt.Errorf("ошибка загрузки CA: %w", err)
    }

    if err := proxy.StartProxy(port); err != nil {
        return fmt.Errorf("ошибка запуска прокси: %w", err)
    }

    return nil
}
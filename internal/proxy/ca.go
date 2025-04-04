package proxy

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type CertificateManager struct {
	rootCertificate *x509.Certificate
	privateKey      *rsa.PrivateKey
}

var certManager = &CertificateManager{}

func InitializeCertificateAuthority(certPath, keyPath string) error {
	certData, keyData, err := loadCertificateFiles(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("ошибка загрузки файлов сертификатов: %w", err)
	}

	if err := certManager.processCertificateData(certData, keyData); err != nil {
		return fmt.Errorf("ошибка обработки данных сертификатов: %w", err)
	}

	return nil
}

func loadCertificateFiles(certPath, keyPath string) ([]byte, []byte, error) {
	certContent, err := readSecureFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("невозможно прочитать сертификат: %w", err)
	}

	keyContent, err := readSecureFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("невозможно прочитать ключ: %w", err)
	}

	return certContent, keyContent, nil
}

func readSecureFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла %s: %w", path, err)
	}

	if len(content) == 0 {
		return nil, fmt.Errorf("файл %s пуст", path)
	}

	return content, nil
}

func (cm *CertificateManager) processCertificateData(certData, keyData []byte) error {
	cert, err := cm.parseCertificateBlock(certData)
	if err != nil {
		return err
	}

	key, err := cm.parsePrivateKeyBlock(keyData)
	if err != nil {
		return err
	}

	cm.rootCertificate = cert
	cm.privateKey = key
	return nil
}

func (cm *CertificateManager) parseCertificateBlock(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) > 0 {
		return nil, fmt.Errorf("некорректный формат PEM сертификата")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("неверный тип блока PEM: %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата: %w", err)
	}

	return cert, nil
}

func (cm *CertificateManager) parsePrivateKeyBlock(data []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) > 0 {
		return nil, fmt.Errorf("некорректный формат PEM ключа")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("неверный тип блока PEM: %s", block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга приватного ключа: %w", err)
	}

	return key, nil
}

func GetCertificateAndKey() (*x509.Certificate, *rsa.PrivateKey) {
	return certManager.rootCertificate, certManager.privateKey
}

func LoadCA(certPath, keyPath string) error {
	return InitializeCertificateAuthority(certPath, keyPath)
}

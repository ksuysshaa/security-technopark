package proxy

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "sync"
    "time"
)

type CertificateStore struct {
    cache     map[string]*tls.Certificate
    mutex     sync.RWMutex
    generator *CertificateGenerator
}

type CertificateGenerator struct {
    keySize       int
    organization  string
    validityDays  int
    rootCert      *x509.Certificate
    rootKey       *rsa.PrivateKey
}

type CertificateOptions struct {
    CommonName  string
    ValidFrom   time.Time
    ValidFor    time.Duration
    KeyUsage    x509.KeyUsage
    ExtKeyUsage []x509.ExtKeyUsage
}

var defaultStore = NewCertificateStore()

func NewCertificateStore() *CertificateStore {
    return &CertificateStore{
        cache: make(map[string]*tls.Certificate),
        generator: &CertificateGenerator{
            keySize:      2048,
            organization: "MITM Security Proxy",
            validityDays: 30,
        },
    }
}

func GetCertificate(hostname string) (*tls.Certificate, error) {
    return defaultStore.GetOrCreateCertificate(hostname)
}

func (s *CertificateStore) GetOrCreateCertificate(hostname string) (*tls.Certificate, error) {
    s.mutex.RLock()
    cert, exists := s.cache[hostname]
    s.mutex.RUnlock()
    
    if exists {
        return cert, nil
    }

    return s.createAndStoreCertificate(hostname)
}

func (s *CertificateStore) createAndStoreCertificate(hostname string) (*tls.Certificate, error) {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    if cert, exists := s.cache[hostname]; exists {
        return cert, nil
    }

    cert, err := s.generator.generateCertificate(hostname)
    if err != nil {
        return nil, fmt.Errorf("ошибка генерации сертификата: %w", err)
    }

    s.cache[hostname] = cert
    return cert, nil
}

func (g *CertificateGenerator) generateCertificate(hostname string) (*tls.Certificate, error) {
    if err := g.validateConfiguration(); err != nil {
        return nil, err
    }

    privateKey, err := g.generatePrivateKey()
    if err != nil {
        return nil, err
    }

    template, err := g.createCertificateTemplate(hostname)
    if err != nil {
        return nil, err
    }

    return g.createTLSCertificate(template, privateKey)
}

func (g *CertificateGenerator) validateConfiguration() error {
    if g.rootCert == nil || g.rootKey == nil {
        return fmt.Errorf("корневой сертификат или ключ не инициализированы")
    }
    return nil
}

func (g *CertificateGenerator) generatePrivateKey() (*rsa.PrivateKey, error) {
    key, err := rsa.GenerateKey(rand.Reader, g.keySize)
    if err != nil {
        return nil, fmt.Errorf("ошибка генерации RSA ключа: %w", err)
    }
    return key, nil
}

func (g *CertificateGenerator) createCertificateTemplate(hostname string) (*x509.Certificate, error) {
    serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
    if err != nil {
        return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
    }

    now := time.Now()
    return &x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            CommonName:   hostname,
            Organization: []string{g.organization},
        },
        NotBefore:             now.Add(-time.Hour),
        NotAfter:              now.Add(time.Duration(g.validityDays) * 24 * time.Hour),
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        DNSNames:             []string{hostname},
    }, nil
}

func (g *CertificateGenerator) createTLSCertificate(template *x509.Certificate, privateKey *rsa.PrivateKey) (*tls.Certificate, error) {
    certDER, err := x509.CreateCertificate(
        rand.Reader,
        template,
        g.rootCert,
        &privateKey.PublicKey,
        g.rootKey,
    )
    if err != nil {
        return nil, fmt.Errorf("ошибка создания сертификата: %w", err)
    }

    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certDER,
    })

    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })

    tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        return nil, fmt.Errorf("ошибка создания TLS сертификата: %w", err)
    }

    return &tlsCert, nil
}

func getOrGenerateCert(host string) (*tls.Certificate, error) {
    return GetCertificate(host)
}

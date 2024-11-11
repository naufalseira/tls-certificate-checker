package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "net"
    "os"
    "strings"
    "time"
)

// CertificateInfo menyimpan informasi sertifikat untuk output JSON
type CertificateInfo struct {
    Host            string    `json:"host"`
    TLSVersion      string    `json:"tls_version"`
    CipherSuite     string    `json:"cipher_suite"`
    Issuer          string    `json:"issuer"`
    Subject         string    `json:"subject"`
    ValidFrom       time.Time `json:"valid_from"`
    ValidUntil      time.Time `json:"valid_until"`
    DNSNames        []string  `json:"dns_names"`
    IsValid         bool      `json:"is_valid"`
    ExpirationDays  int       `json:"days_until_expiration"`
    SecurityRating  string    `json:"security_rating"`
    Warnings        []string  `json:"warnings"`
}

func main() {
    var address string
    fmt.Println("--------------------------------------------------------")
    fmt.Println("|   SSL/TLS Certificate Checker and Security Analyzer  |")
    fmt.Println("--------------------------------------------------------")
    fmt.Println("Enter Web Address (example: binusmaya.com): ")
	fmt.Print(">")
    fmt.Scanln(&address)

    info, err := checkCertificate(address)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    // Tampilkan hasil dalam format yang mudah dibaca
    displayResults(info)

    // Simpan hasil ke file JSON
    saveToJSON(info)
}

func checkCertificate(address string) (*CertificateInfo, error) {
    address = normalizeAddress(address)
    
    conn, err := net.DialTimeout("tcp", address, 5*time.Second)
    if err != nil {
        return nil, fmt.Errorf("connection failure: %v", err)
    }
    defer conn.Close()

    config := &tls.Config{
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS10,
    }

    tlsConn := tls.Client(conn, config)
    err = tlsConn.Handshake()
    if err != nil {
        return nil, fmt.Errorf("TLS handshake failure: %v", err)
    }
    defer tlsConn.Close()

    state := tlsConn.ConnectionState()
    cert := state.PeerCertificates[0]

    info := &CertificateInfo{
        Host:           strings.Split(address, ":")[0],
        TLSVersion:     tlsVersionString(state.Version),
        CipherSuite:    tls.CipherSuiteName(state.CipherSuite),
        Issuer:         getIssuerName(cert),
        Subject:        getSubjectName(cert),
        ValidFrom:      cert.NotBefore,
        ValidUntil:     cert.NotAfter,
        DNSNames:       cert.DNSNames,
        IsValid:        time.Now().Before(cert.NotAfter),
        ExpirationDays: int(time.Until(cert.NotAfter).Hours() / 24),
    }

    info.SecurityRating = calculateSecurityRating(state)
    info.Warnings = generateWarnings(info)

    return info, nil
}

func normalizeAddress(address string) string {
    address = strings.TrimPrefix(address, "https://")
    address = strings.TrimPrefix(address, "http://")
    if !strings.Contains(address, ":") {
        address = address + ":443"
    }
    return address
}

func getIssuerName(cert *x509.Certificate) string {
    if len(cert.Issuer.Organization) > 0 {
        return cert.Issuer.Organization[0]
    }
    return "Not available"
}

func getSubjectName(cert *x509.Certificate) string {
    if len(cert.Subject.CommonName) > 0 {
        return cert.Subject.CommonName
    }
    return "Not available"
}

func calculateSecurityRating(state tls.ConnectionState) string {
    switch {
    case state.Version >= tls.VersionTLS13:
        return "Excellent"
    case state.Version >= tls.VersionTLS12:
        return "Good"
    case state.Version >= tls.VersionTLS11:
        return "Fair"
    default:
        return "Poor"
    }
}

func generateWarnings(info *CertificateInfo) []string {
    var warnings []string

    // Periksa expired/mendekati expired
    if !info.IsValid {
        warnings = append(warnings, "The certificate has expired!")
    } else if info.ExpirationDays < 30 {
        warnings = append(warnings, fmt.Sprintf("The certificate will expire in %d days", info.ExpirationDays))
    }

    // Periksa versi TLS
    if strings.Contains(info.TLSVersion, "1.0") || strings.Contains(info.TLSVersion, "1.1") {
        warnings = append(warnings, "Using an outdated version of TLS")
    }

    return warnings
}

func displayResults(info *CertificateInfo) {
    fmt.Println("")
    fmt.Println("--------------------------------------------------------")
    fmt.Println("|                    Analysis Result                   |")
    fmt.Println("--------------------------------------------------------")
    fmt.Printf("Host            : %s\n", info.Host)
    fmt.Printf("TLS Version     : %s\n", info.TLSVersion)
    fmt.Printf("Cipher Suite    : %s\n", info.CipherSuite)
    fmt.Printf("Issuer          : %s\n", info.Issuer)
    fmt.Printf("Subject         : %s\n", info.Subject)
    fmt.Printf("Valid from      : %s\n", info.ValidFrom.Format("2006-01-02"))
    fmt.Printf("Valid until     : %s\n", info.ValidUntil.Format("2006-01-02"))
    fmt.Printf("Time remaining  : %d days\n", info.ExpirationDays)
    fmt.Printf("Security Rating : %s\n", info.SecurityRating)
    
    if len(info.DNSNames) > 0 {
        fmt.Println("\nAlternate DNS name:")
        for _, dns := range info.DNSNames {
            fmt.Printf("- %s\n", dns)
        }
    }

    if len(info.Warnings) > 0 {
        fmt.Println("\nWarning:")
        for _, warning := range info.Warnings {
            fmt.Printf("! %s\n", warning)
        }
    }
}

func saveToJSON(info *CertificateInfo) {
    filename := fmt.Sprintf("cert_check_%s_%s.json", 
        info.Host, 
        time.Now().Format("20060102_150405"))

    data, err := json.MarshalIndent(info, "", "    ")
    if err != nil {
        fmt.Printf("Error while savinf to JSON: %v\n", err)
        return
    }

    err = os.WriteFile(filename, data, 0644)
    if err != nil {
        fmt.Printf("Error while writing file: %v\n", err)
        return
    }

    fmt.Printf("\nResult has been save to %s\n", filename)
}

func tlsVersionString(version uint16) string {
    versionMap := map[uint16]string{
        tls.VersionTLS10: "TLS 1.0",
        tls.VersionTLS11: "TLS 1.1",
        tls.VersionTLS12: "TLS 1.2",
        tls.VersionTLS13: "TLS 1.3",
    }
    if str, ok := versionMap[version]; ok {
        return str
    }
    return "Unknown"
}
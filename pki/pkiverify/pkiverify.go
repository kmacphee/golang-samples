package main

import (
    "bufio"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/binary"
    "fmt"
    "math/big"
    "net"
    "os"
    "time"
    
    "github.com/urfave/cli"
)

func main() {
    app := cli.NewApp()
    app.Usage = "Create and verify certificates."
    app.Commands = []cli.Command {
        {
            Name: "rootca",
            ShortName: "r",
            Usage: "Start a RootCA server and respond to certificate requests.",
            Flags: []cli.Flag {
                cli.StringFlag {
                    Name: "port",
                    Usage: "The socket port to listen to requests on.",
                    Value: "cert",
                },
            },
            Action: func(c *cli.Context) error {
                return startRootCAServer(c.String("port"))
            },
        },
        {
            Name: "newcert",
            ShortName: "n",
            Usage: "Create new certificate, signed by the given RootCA.",
            Flags: []cli.Flag {
                cli.StringFlag {
                    Name: "rootca",
                    Usage: "Address of a RootCA server that will sign the new certificate.",
                    Value: "",
                },
            },
            Action: func(c *cli.Context) error {
                return newSignedCertificate(c.String("rootca"))
            },
        },
    }
    
    app.Run(os.Args)
}

// Generate a self-signed root certificate and start listening for certificate signing requests on the given port.
func startRootCAServer(port string) error {
    // Create 2048-bit private key for RootCA instance
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    fmt.Println("Created RSA key pair for RootCA.")
    
    // Create root certificate template
    notBefore := time.Now()
    notAfter := notBefore.Add(time.Hour * 24 * 365)
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    template := x509.Certificate {
        SerialNumber: serialNumber,
        Subject: pkix.Name {
            Organization: []string{"AnchorLoop"},
        },
        NotBefore: notBefore,
        NotAfter: notAfter,
        KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
        BasicConstraintsValid: true,
        IsCA: true,
    }
    
    // Create self-signed root certificate
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    fmt.Println("Created Self-Signed Root Certificate.")
    rootCert, err := x509.ParseCertificate(derBytes)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    
    err =  handleCertificateRequest(port, rootCert, privateKey)
    if err != nil {
        return cli.NewExitError(err, -1)
    }

    return nil
}

// Listen for and respond to any certificate signing requests on the given port. Create a new client certificate signed
// by the RootCA private key and send both the new and root certificates back to the client.
func handleCertificateRequest(port string, rootCert *x509.Certificate, privateKey *rsa.PrivateKey) error {
    // Listen, wait and accept connection
    fmt.Println("Listening for Certificate Signing Request on port", port)
    ln, err := net.Listen("tcp", ":" + port)
    if err != nil {
        return err
    }
    conn, err := ln.Accept()
    if err != nil {
        return err
    }
    defer conn.Close()
    fmt.Println("Accepted Certificate Signing Request.")
    
    // Read two-byte header containing size of the ASN1 data of the certificate request
    reader := bufio.NewReader(conn)
    header := make([]byte, 2)
    _, err = reader.Read(header)
    if err != nil {
        return err
    }
    asn1DataSize := binary.LittleEndian.Uint16(header)
    
    // Now read that number of bytes and parse the certificate request
    asn1Data := make([]byte, asn1DataSize)
    _, err = reader.Read(asn1Data)
    if err != nil {
        return err
    }
    fmt.Println("Received Certificate Signing Request.")
    certReq, err := x509.ParseCertificateRequest(asn1Data)
    if err != nil {
        return err
    }
    
    // Create template for certificate creation, uses properties from the request and root certificate.
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
        return err
    }
    template := x509.Certificate {
        Signature: certReq.Signature,
        SignatureAlgorithm: certReq.SignatureAlgorithm,
        
        PublicKeyAlgorithm: certReq.PublicKeyAlgorithm,
        PublicKey: certReq.PublicKey,
        
        SerialNumber: serialNumber,
        Issuer: rootCert.Subject,
        Subject: certReq.Subject,
        NotBefore: time.Now(),
        NotAfter: time.Now().Add(time.Hour * 24 * 365),
        KeyUsage: x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    
    // Create certificate from template and root certificate, signed by the RootCA's private key.
    certData, err := x509.CreateCertificate(rand.Reader, &template, rootCert, template.PublicKey, privateKey)
    if err != nil {
        return err
    }
    fmt.Println("Created Certificate from CSR, signed by RootCA's Private Key.")
    
    // Transmit newly created certificate data back over the connection.
    writer := bufio.NewWriter(conn)
    // The number of bytes that make up the new certificate go first.
    certHeader := make([]byte, 2)
    binary.LittleEndian.PutUint16(certHeader, uint16(len(certData)))
    _, err = writer.Write(certHeader)
    if err != nil {
        return err
    }
    // Now write the certificate data.
    _, err = writer.Write(certData)
    if err != nil {
        return err
    }
    // Now write the size of the root certificate, which will be needed to validate the new certificate
    rootCertHeader := make([]byte, 2)
    binary.LittleEndian.PutUint16(rootCertHeader, uint16(len(rootCert.Raw)))
    _, err = writer.Write(rootCertHeader)
    if err != nil {
        return err
    }
    // Now write the root certificate data.
    _, err = writer.Write(rootCert.Raw)
    if err != nil {
        return err
    }
    // Flush all the data.
    err = writer.Flush()
    if err != nil {
        return err
    }
    fmt.Println("Transmitted client Certificate and Root Certificate back to client.")
    
    return nil
}

// Create a new client certificate by sending a certificate signing request to the given RootCA.
func newSignedCertificate(rootCA string) error {
    // Create 2048-bit private key for the new certificate
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    fmt.Println("Created RSA key pair for client.")
    
    // Create CSR template
    certReqTemplate := x509.CertificateRequest {
        SignatureAlgorithm: x509.SHA256WithRSA,
        Subject: pkix.Name {
            Organization: []string{"AnchorLoop Client"},
        },
    }
    
    // Create certificate request
    derBytes, err := x509.CreateCertificateRequest(rand.Reader, &certReqTemplate, privateKey)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    fmt.Println("Created Certificate Signing Request for client.")
    
    // Dial RootCA server and transmit certificate request
    conn, err := net.Dial("tcp", rootCA)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    defer conn.Close()
    fmt.Println("Successfully connected to Root Certificate Authority.")
    
    writer := bufio.NewWriter(conn)
    // Send two-byte header containing the number of ASN1 bytes transmitted.
    header := make([]byte, 2)
    binary.LittleEndian.PutUint16(header, uint16(len(derBytes)))
    _, err = writer.Write(header)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    // Now send the certificate request data
    _, err = writer.Write(derBytes)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    err = writer.Flush()
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    fmt.Println("Transmitted Certificate Signing Request to RootCA.")
    
    // The RootCA will now send our signed certificate back for us to read.
    reader := bufio.NewReader(conn)
    // Read header containing the size of the ASN1 data.
    certHeader := make([]byte, 2)
    _, err = reader.Read(certHeader)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    certSize := binary.LittleEndian.Uint16(certHeader)
    // Now read the certificate data.
    certBytes := make([]byte, certSize)
    _, err = reader.Read(certBytes)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    fmt.Println("Received new Certificate from RootCA.")
    newCert, err := x509.ParseCertificate(certBytes)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    
    // Finally, the RootCA will send its own certificate back so that we can validate the new certificate.
    rootCertHeader := make([]byte, 2)
    _, err = reader.Read(rootCertHeader)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    rootCertSize := binary.LittleEndian.Uint16(rootCertHeader)
    // Now read the certificate data.
    rootCertBytes := make([]byte, rootCertSize)
    _, err = reader.Read(rootCertBytes)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    fmt.Println("Received Root Certificate from RootCA.")
    rootCert, err := x509.ParseCertificate(rootCertBytes)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    
    err = validateCertificate(newCert, rootCert)
    if err != nil {
        return cli.NewExitError(err, -1)
    }

    return nil
}

// Validate the new certificate by verifying the chain of trust between it and the certificate of the RootCA that
// signed it.
func validateCertificate(newCert *x509.Certificate, rootCert *x509.Certificate) error {
    roots := x509.NewCertPool()
    roots.AddCert(rootCert)
    verifyOptions := x509.VerifyOptions {
        Roots: roots,
        KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    
    _, err := newCert.Verify(verifyOptions)
    if err != nil {
        fmt.Println("Failed to verify chain of trust.")
        return err
    }
    fmt.Println("Successfully verified chain of trust.")
    
    return nil
}

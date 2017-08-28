package main

import (
    "bufio"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/binary"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"

    "github.com/urfave/cli"
)

func main() {
    app := cli.NewApp()
    app.Usage = "Create RSA key pairs and transmit encrypted messages."
    app.Commands = []cli.Command {
        {
            Name: "keygen",
            ShortName: "k",
            Usage: "Generate a public/private key pair.",
            Flags: []cli.Flag {
                cli.StringFlag {
                    Name: "output, o",
                    Usage: "Directory to output generated keys to.",
                    Value: ".",
                },
                cli.IntFlag {
                    Name: "bits, b",
                    Usage: "Size of the generated keys.",
                },
            },
            Action: func(c *cli.Context) error {
                return keygen(c.String("output"), c.Int("bits"))
            },
        },
        {
            Name: "converse",
            ShortName: "c",
            Usage: "Send and receive encrypted messages to/from a target.",
            Flags: []cli.Flag {
                cli.StringFlag {
                    Name: "target, t",
                    Usage: "The target to converse with.",
                    Value: "localhost:35196",
                },
                cli.StringFlag {
                    Name: "keys, k",
                    Usage: "Directory containing keys to converse with.",
                    Value: ".",
                },
                cli.StringFlag {
                    Name: "messages, m",
                    Usage: "File containing messages to encrypt and send.",
                    Value: "",
                },
            },
            Action: func(c *cli.Context) error {
                return converse(c.String("target"), c.String("keys"), c.String("messages"))
            },
        },
        {
            Name: "listen",
            ShortName: "l",
            Usage: "Listen for a message, then send and receive encrypted messages.",
            Flags: []cli.Flag {
                cli.StringFlag {
                    Name: "port, p",
                    Usage: "Port to listen on.",
                    Value: "35196",
                },
                cli.StringFlag {
                    Name: "keys, k",
                    Usage: "Directory containing keys to converse with.",
                    Value: ".",
                },
                cli.StringFlag {
                    Name: "messages, m",
                    Usage: "File containing messages to encrypt and send.",
                    Value: "",
                },
            },
            Action: func(c *cli.Context) error {
                return listen(c.String("port"), c.String("keys"), c.String("messages"))
            },
        },
    }

    app.Run(os.Args)
}

// Generate an RSA key pair in the given output directory. The strength of the keys are
// determined by the number of bits used. The private key is output to a file called 'private'
// and the public key is output to a file called 'public'.
func keygen(output string, bits int) error {
    // Generate key pair.
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return cli.NewExitError(err, -1)
    }

    // Encode and output private key to file in output dir.
    pemPrivateKey := &pem.Block {
        Type: "PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    }

    privateKeyFile, err := os.Create(output + "/private")
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    defer privateKeyFile.Close()

    err = pem.Encode(privateKeyFile, pemPrivateKey)
    if err != nil {
        return cli.NewExitError(err, -1)
    }

    // Encode and output public key to file in output dir.
    publicKey := privateKey.PublicKey
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    pemPublicKey := &pem.Block {
        Type: "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    publicKeyFile, err := os.Create(output + "/public")
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    defer publicKeyFile.Close()

    err = pem.Encode(publicKeyFile, pemPublicKey)
    if err != nil {
        return cli.NewExitError(err, -1)
    }

    return nil
}

// Send and receive excrypted messages with the provided target. The instance in 'converse' mode
// is the instance which sends first and receives second, i.e. initiates the key exchange, sends
// the first message, etc. 'keys' is the directory that contains the public and private keys
// output by 'keygen'. 'messages' is a text file containing messages to encrypt and transmit.
func converse(target string, keys string, messages string) error {
    logFile, _ := os.Create("./converse.log")
    defer logFile.Close()
    logger := log.New(logFile, "", log.LstdFlags | log.Lshortfile)

    // Load keys
    logger.Println("Loading keys from:", keys)
    privateKey, publicKey, err := loadKeys(keys)
    if err != nil {
        logger.Println("Failed to load keys.", err)
        return cli.NewExitError(err, -1)
    }
    if privateKey != nil && publicKey != nil {
        logger.Println("Successfully loaded private and public keys")
    }

    // Load messages
    lines, err := loadMessages(messages)
    if err != nil {
        logger.Println("Failed to load messages from file:", messages,".", err)
        return cli.NewExitError(err, -1)
    }
    logger.Printf("Successfully loaded %d lines from messages file: %s\n", len(lines), messages)

    // Dial target
    conn, err := net.Dial("tcp", target)
    if err != nil {
        logger.Printf("Failed to dial %s. %s\n", target, err)
        return cli.NewExitError(err, -1)
    }
    logger.Println("Successfully dialed", target)
    defer conn.Close()

    // Send public key to target
    writer := bufio.NewWriter(conn)
    err = sendPublicKey(writer, publicKey, logger)
    if err != nil {
        return cli.NewExitError(err, -1)
    }

    // Receive public key from target
    reader := bufio.NewReader(conn)
    targetPublicKey, err := receivePublicKey(reader, logger)
    if err != nil {
        return cli.NewExitError(err, -1)
    }
    if targetPublicKey == nil {
        err = errors.New("Failed to receive public key from target")
        logger.Println(err)
        return cli.NewExitError(err, -1)
    }

    // Send and receive messages with the target, encrypting with the receiver's public key and
    // decrypting with our private key.
    for _, line := range lines {
        fmt.Println("Sending:", line)
        err := encryptSignAndSend(line, writer, targetPublicKey, privateKey, logger)
        if err != nil {
            return cli.NewExitError(err, -1)
        }

        received, err := receiveDecryptAndVerify(reader, privateKey, targetPublicKey, logger)
        if err != nil {
            return cli.NewExitError(err, -1)
        }
        fmt.Println("Received:", received, "\n")
    }

    return nil
}

// Listen on a port and trade encrypted messages with any accepted connection. An instance in
// 'listen' mode receives first and sends second. 'port' is the number of the TCP port to listen
// on, 'keys' is the directory containing keys which are the output of 'keygen' and 'messages' is
// a text file containing messages to exchange.
func listen(port string, keys string, messages string) error {
    logFile, _ := os.Create("./listen.log")
    defer logFile.Close()
    logger := log.New(logFile, "", log.LstdFlags | log.Lshortfile)

    // Load keys
    logger.Println("Loading keys from:", keys)
    privateKey, publicKey, err := loadKeys(keys)
    if err != nil {
        logger.Println("Failed to load keys.", err)
        return cli.NewExitError(err, -1)
    }
    if privateKey != nil && publicKey != nil {
        logger.Println("Successfully loaded private and public keys")
    }

    // Load messages
    lines, err := loadMessages(messages)
    if err != nil {
        logger.Printf("Failed to load messages from file: %s. %s\n", messages, err)
        return cli.NewExitError(err, -1)
    }
    logger.Printf("Successfully loaded %d lines from messages file: %s\n", len(lines), messages)

    // Listen, wait and accept connection
    ln, err := net.Listen("tcp", ":" + port)
    if err != nil {
        logger.Printf("Listen on port %d failed. %s\n", port, err)
        return cli.NewExitError(err, -1)
    }
    conn, err := ln.Accept()
    if err != nil {
        logger.Println("Failed to accept connection on port:", port)
    }
    defer conn.Close()

    // Receive public key from accepted connection
    reader := bufio.NewReader(conn)
    targetPublicKey, err := receivePublicKey(reader, logger)
    if err != nil {
        return cli.NewExitError(err, -1)
    }

    // Send public key to target
    writer:= bufio.NewWriter(conn)
    err = sendPublicKey(writer, publicKey, logger)
    if err != nil {
        cli.NewExitError(err, -1)
    }

    if targetPublicKey == nil {
        err = errors.New("Failed to receive public key from target")
        logger.Println(err)
        return cli.NewExitError(err, -1)
    }

    // Receive and send messages with the target, encrypting with the received public key and 
    // decrypting with our private key.
    for _, line := range lines {
        received, err := receiveDecryptAndVerify(reader, privateKey, targetPublicKey, logger)
        if err != nil {
            return cli.NewExitError(err, -1)
        }
        fmt.Println("Received: " + received)
        fmt.Println("Sending: " + line + "\n")
        err = encryptSignAndSend(line, writer, targetPublicKey, privateKey, logger)
        if err != nil {
            return cli.NewExitError(err, -1)
        }
    }

    return nil
}

// Load RSA keys from files 'private' and 'public' in the given directory.
func loadKeys(directory string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
    // Load and decode private key from file
    privateKeyFile, err := os.Open(directory + "/private")
    if err != nil {
        return nil, nil, err
    }
    defer privateKeyFile.Close()
    bytes, err := ioutil.ReadAll(privateKeyFile)
    if err != nil {
        return nil, nil, err
    }
    pemPrivateKey, _ := pem.Decode(bytes)
    if pemPrivateKey == nil || pemPrivateKey.Type != "PRIVATE KEY" {
        return nil, nil, errors.New("Failed to decode private key")
    }
    privateKey, err := x509.ParsePKCS1PrivateKey(pemPrivateKey.Bytes)
    if err != nil {
        return nil, nil, err
    }

    // Load and decode public key from file
    publicKeyFile, err := os.Open(directory + "/public")
    if err != nil {
        return privateKey, nil, err
    }
    defer publicKeyFile.Close()
    bytes, err = ioutil.ReadAll(publicKeyFile)
    if err != nil {
        return privateKey, nil, err
    }
    pemPublicKey, _ := pem.Decode(bytes)
    if pemPublicKey == nil || pemPublicKey.Type != "PUBLIC KEY" {
        return privateKey, nil, errors.New("Failed to decode public key")
    }
    publicKey, err := x509.ParsePKIXPublicKey(pemPublicKey.Bytes)
    if err != nil {
        return privateKey, nil, err
    }

    return privateKey, publicKey.(*rsa.PublicKey), nil
}

// Load messages from the given file. Each line is returned in a slice of strings.
func loadMessages(messages string) ([]string, error) {
    messagesFile, err := os.Open(messages)
    if err != nil {
        return nil, cli.NewExitError(err, -1)
    }
    defer messagesFile.Close()
    var lines []string
    scanner := bufio.NewScanner(messagesFile)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }

    return lines, scanner.Err()
}

// Writes the given RSA public key to the ostream wrapped by 'writer'. Used to send our instance's
// public key in a key exchange. First we send 2 bytes that represent the size of the key, which
// differs based on how many bits it was generated with. This tells the receiver how many bytes to
// read off the wire to receive the key, as there isn't a sensible delimiting byte we could use.
// Then we send our x509-encoded public key.
func sendPublicKey(writer *bufio.Writer, publicKey *rsa.PublicKey, logger *log.Logger) error {
    bytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        logger.Println("Failed to marshal public key. ", err)
        return err
    }

    // First 2 bytes will tell the receiver how many bytes long the public key is, so that it
    // knows how many to read.
    header := make([]byte, 2)
    binary.LittleEndian.PutUint16(header, uint16(len(bytes)))
    _, err = writer.Write(header)
    if err != nil {
        logger.Println("Failed to write public key header.", err)
        return err
    }

    // Now send the public key
    _, err = writer.Write(bytes)
    if err != nil {
        logger.Println("Failed to write public key.", err)
        return err
    }
    err = writer.Flush()
    if err != nil {
        logger.Println("Failed to transmit public key. ", err)
    }
    logger.Printf("Sent public key: %x.\n", bytes)

    return nil
}

// Receives and parses an RSA public key from the istream wrapped by 'reader'. The first two
// bytes read tell us how large the key is, then we read that many bytes out and parse the result
// into an rsa.PublicKey.
func receivePublicKey(reader *bufio.Reader, logger *log.Logger) (*rsa.PublicKey, error) {
    // Read the first 2 bytes off the wire first, this tells us the number of remaining bytes
    // we need to read.
    header := make([]byte, 2)
    _, err := reader.Read(header)
    if err != nil {
        logger.Println("Failed to read public key header.", err)
        return nil, err
    }
    size := binary.LittleEndian.Uint16(header)
    logger.Printf("Received header. Incoming public key is %d bytes long.", size)

    // Now read the public key.
    bytes := make([]byte, size)
    _, err = reader.Read(bytes)
    if err != nil {
        logger.Println("Failed to read public key. ", err)
        return nil, err
    }
    logger.Printf("Received public key: %x.\n", bytes)

    publicKey, err := x509.ParsePKIXPublicKey(bytes)
    if err != nil {
        logger.Println("Failed to parse public key. ", err)
        return nil, err
    }

    return publicKey.(*rsa.PublicKey), nil
}

// Encrypts the given message with the given RSA public key, then writes it to the ostream wrapped
// by 'writer'. The SHA256 hash of the message is signed with our private key and sent also.
func encryptSignAndSend(message string, writer *bufio.Writer, publicKey *rsa.PublicKey,
        privateKey *rsa.PrivateKey, logger *log.Logger) error {

    logger.Println("Sending (plaintext): " + message)

    // Encrypt message
    label := []byte("pkcrypto")
    messageBytes := []byte(message)
    ciphertext, err :=  rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, messageBytes,
        label)
    if err != nil {
        logger.Println("Failed to encrypt message.", err)
        return err
    }

    // Sign the hash of message
    hash := sha256.New()
    hash.Write(messageBytes)
    hashed := hash.Sum(nil)
    signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed, nil)
    if err != nil {
        logger.Println("Failed to sign message.", err)
        return err
    }

    // First two bytes over the wire tell the receiver how large any ciphertext is, so that it 
    // knows how many bytes to read.
    header := make([]byte, 2)
    binary.LittleEndian.PutUint16(header, uint16(len(ciphertext)))

    logger.Printf("Sending (ciphertext): %x\n", ciphertext)
    _, err = writer.Write(header)
    if err != nil {
        logger.Println("Failed to write ciphertext header to target.", err)
    }
    // Next write the ciphertext
    _, err = writer.Write(ciphertext)
    if err != nil {
        logger.Println("Failed to write ciphertext to target.", err)
        return err
    }
    // Then we send the length of the signature. As this is from our private key, not the
    // target's public key, it isn't necessarily the same size as the ciphertext.
    sigHeader := make([]byte, 2)
    binary.LittleEndian.PutUint16(sigHeader, uint16(len(signature)))
    _, err = writer.Write(sigHeader)
    if err != nil {
        logger.Println("Failed to write signature header.", err)
        return err
    }
    // Finally we write our signature
    logger.Printf("Signature: %x\n", signature)
    _, err = writer.Write(signature)
    if err != nil {
        logger.Println("Failed to write signature.", err)
        return err
    }
    // Flush all the bytes
    err = writer.Flush()
    if err != nil  {
        logger.Println("Failed to transmit encrypted message to target.", err)
        return err
    }

    return nil
}

// Receives an encrypted message and a signature from the istream wrapped by 'reader', decrypts the
// message with our RSA private key, calculates the SHA256 hash of the plaintext and validates the
// signature. Returns the plaintext message.
func receiveDecryptAndVerify(reader *bufio.Reader, privateKey *rsa.PrivateKey,
        publicKey *rsa.PublicKey, logger *log.Logger) (string, error) {

    // Read the two byte header, which tells us the length (bytes) of the ciphertext.
    header := make([]byte, 2)
    _, err := reader.Read(header)
    if err != nil {
        logger.Println("Failed to read ciphertext header.", err)
        return "", err
    }
    size := binary.LittleEndian.Uint16(header)
    logger.Printf("Received header. Incoming ciphertext is %d bytes long.", size)
    // Read ciphertext
    ciphertext := make([]byte, size)
    _, err = reader.Read(ciphertext)
    if err != nil {
        logger.Println("Failed to read ciphertext from target.", err)
        return "", err
    }
    logger.Printf("Received (ciphertext): %x\n", ciphertext)
    // Read another two byte header, which tells us the length (bytes) of the signature.
    sigHeader := make([]byte, 2)
    _, err = reader.Read(sigHeader)
    if err != nil {
        logger.Println("Failed to read signature header.", err)
        return "", err
    }
    sigSize := binary.LittleEndian.Uint16(sigHeader)
    logger.Printf("Received signature header. Incoming signature is %d bytes long.", sigSize)
    // Read signature
    signature := make([]byte, sigSize)
    _, err = reader.Read(signature)
    if err != nil {
        logger.Println("Failed to read signature from target.", err)
        return "", err
    }
    logger.Printf("Received signature: %x\n", signature)

    // Decrypt message
    label := []byte("pkcrypto")
    plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, label)
    if err != nil {
        logger.Println("Failed to decrypt cipher.", err)
        return "", err
    }
    logger.Printf("Received (plaintext): %s\n", plaintext)

    // Hash plaintext and verify signature
    hash:= sha256.New()
    hash.Write(plaintext)
    hashed := hash.Sum(nil)
    err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, signature, nil)
    if err != nil {
        logger.Println("Failed signature verification.", err)
        return "", err
    }
    logger.Println("Signature verified.")

    return string(plaintext), nil
}

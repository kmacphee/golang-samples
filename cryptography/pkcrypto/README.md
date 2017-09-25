# pkcrypto
**Supporting blog post:** https://anchorloop.com/2017/09/01/security-iq-public-key-cryptography/

A sample program that demonstrates public key (RSA) encryption (OEAP) and message signing (PSS) in Go.

An instance of the program in `listen` mode and an instance in `converse` mode can pass encrypted messages over a network.

## Usage

### Generating RSA key pairs

Generate an RSA key pair in the `output` directory with the given strength in `bits`.

```
pkcrypto keygen --output keys --bits 2048
```

### Starting in listen mode

Execute the `listen` command to listen for a public key exchange on the given `port`. Then send and receive encrypted `messages`.

```
pkcrypto listen --port 35196 --keys ./keys --messages ./messages.txt
```

### Starting in converse mode

Initiate a public key exchange with `target`, then send and receive encrypted `messages`.

```
pkcrypto converse --keys keys --target localhost:35196 --messages messages.txt
```
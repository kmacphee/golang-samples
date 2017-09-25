# pkiverify

**Supporting blog post:**

A sample program that demonstrates certificate signing and chains of trust in Go.

## Usage

### Start a RootCA server

Execute the `rootca` command with an arbitrary `port` to listen for Certificate Signing Requests on.

```
pkiverify rootca --port 35196
```

*Note:* Responds to one CSR only then exits.

### Create and verify a new certificate signed by a RootCA server

Execute the `newcert` command with the address where an instance of the program in `rootca` mode is listening.

```
pkiverify newcert --rootca localhost:35196
```
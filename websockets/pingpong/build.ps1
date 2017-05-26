# Set env params for Linux cross-compilation.
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'

Push-Location .\client
go build client.go
docker build --tag kmacphee/golang-samples/websockets/pingpong/client .
Pop-Location

Push-Location .\server
go build server.go
docker build --tag kmacphee/golang-samples/websockets/pingpong/server .
Pop-Location
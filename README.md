# webhook-interceptor
A Go service to act as an Webhook interceptor 

## Building instructions
mkdir bin
go build -o bin ./cmd/webhook-interceptor

## Testing instructions
curl -v \
-H 'X-Hub-Signature: sha256=eff49d9c699ae04340f1a9a6e1800a7d018864c88ca719e0156ca7a9a55b0f67' \
-d '{"test": 123}' \
http://localhost:8080/test

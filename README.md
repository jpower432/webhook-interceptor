# webhook-interceptor
A Go service to act as a webhook interceptor 

## Building instructions
make build

## Testing instructions
export HEADER=X-Hub-Signature
export WEBHOOK_SECRET="my key"
bin/webhook-interceptor


curl -v \
-H 'X-Hub-Signature: sha256=eff49d9c699ae04340f1a9a6e1800a7d018864c88ca719e0156ca7a9a55b0f67' \
-d '{"test": 123}' \
http://localhost:8080/test

openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=yngwie proxy CA"

openssl genrsa -out cert.key 2048
mkdir -p certs/

openssl req -new -key cert.key -subj "/CN=$1" -sha256 \
  | openssl x509 -req -days 3650 -CA ca.crt -CAkey ca.key -set_serial "$2" \
  -out "certs/$1.crt"
echo "Готов сертификат: certs/$1.crt"
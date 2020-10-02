#!/bin/bash
#openssl genrsa -out server.key 2048
#openssl rsa -in server.key -out server.key.rsa
#openssl req -new -key server.key.rsa -subj /CN=localhost -out server.csr -config openssl.conf
#openssl x509 -req -extensions v3_req -days 365 -in server.csr -signkey server.key.rsa -out server.crt -extfile openssl.conf
#sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /etc/ssl/localhost/localhost.crt
cert=$(cat server.crt)
key=$(cat server.key.rsa)
echo "
package main

const tlsCert = \`${cert}\`

const tlsKey = \`${key}\`
" > certs.go



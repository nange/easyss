#!/bin/bash

# Step1. gen CA certs
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
# created file list: ca-key.pem, ca.csr, ca.pem

# Step2. gen Server certs
echo '{"CN":"easy-server","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server -hostname="172.16.10.1,127.0.0.1" - | cfssljson -bare easy-server
# created file list: easy-server-key.pem, easy-server.csr, easy-server.pem

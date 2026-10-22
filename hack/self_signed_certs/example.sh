#!/bin/bash

# Step1. gen CA certs
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
# created file list: ca-key.pem, ca.csr, ca.pem

# Step2. gen Server certs
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=server -hostname="172.16.10.1" server-csr.json | cfssljson -bare easy-server
# created file list: easy-server-key.pem, easy-server.csr, easy-server.pem

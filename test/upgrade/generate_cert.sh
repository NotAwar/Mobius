#!/bin/bash

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout mobius.key -out mobius.crt -extensions san -config \
  <(echo "[req]";
    echo distinguished_name=req;
    echo "[san]";
    echo subjectAltName=DNS:mobius-a,DNS:mobius-b
    ) \
  -subj "/CN=mobius"

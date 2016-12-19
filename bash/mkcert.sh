#!/bin/bash

openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -out private_key.pem
openssl rsa -in private_key.pem -pubout -out public_key.pem
## RSA keypair

### Create RSA PKCS#8 PEM private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_2048_private.pem

### Generate RSA PKCS#8 PEM public key from RSA PKCS#8 PEM private key
openssl pkey -in rsa_2048_private.pem -pubout -outform PEM -out rsa_2048_public.pem

### Convert RSA private key from PKCS#8 PEM to PKCS#8 DER
openssl pkcs8 -topk8 -nocrypt -in rsa_2048_private.pem -outform DER -out rsa_2048_private.der

## Generate RSA PKCS#8 DER public key from RSA PKCS#8 PEM private key
openssl pkey -in rsa_2048_private.pem -pubout -outform DER -out rsa_2048_public.der

### Convert RSA private key from PKCS#8 DER to PKCS#8 PEM
openssl pkey -inform DER -in rsa_2048_private.der -out rsa_2048_private.pem

### Convert RSA private key from PKCS#8 PEM to PKCS#1 PEM
openssl pkcs8 -nocrypt -in rsa_2048_private.pem -traditional -out rsa_2048_pk1_private.pem

### Convert RSA private key from PKCS#8 PEM to PKCS#1 DER
openssl pkey -in rsa_2048_private.pem -outform DER -out rsa_2048_pk1_private.der

### Convert RSA private key from PKCS#1 PEM to PKCS#8 PEM
openssl pkcs8 -nocrypt -in rsa_2048_pk1_private.pem -topk8 -out rsa_2048_private.pem

## RSA-PSS keypair

### Create RSA-PSS PKCS#8 PEM private key
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256  -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -out rsapss_2048_sha256_private.pem

### Generate RSA PKCS#8 PEM public key from RSA PKCS#8 PEM private key
openssl pkey -in rsapss_2048_sha256_private.pem -pubout -outform PEM -out rsapss_2048_sha256_public.pem

## ECDSA keypair

### Create ECDSA PKCS#8 PEM private key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform PEM -out ecdsa_p256_private.pem

### Generate ECDSA PKCS#8 PEM public key from ECDSA PKCS#8 PEM private key
openssl pkey -in ecdsa_p256_private.pem -pubout -outform PEM -out ecdsa_p256_public.pem

### Convert ECDSA private key from PKCS#8 PEM to PKCS#8 DER
openssl pkcs8 -topk8 -nocrypt -in ecdsa_p256_private.pem -outform DER -out ecdsa_p256_private.der

### Generate ECDSA PKCS#8 DER public key from ECDSA PKCS#8 PEM private key
openssl pkey -in ecdsa_p256_private.pem -pubout -outform DER -out ecdsa_p256_public.der

### Convert ECDSA private key from PKCS#8 DER to PKCS#8 PEM
openssl pkey -inform DER -in ecdsa_p256_private.der -out ecdsa_p256_private.pem

### Convert ECDSA private key from PKCS#8 PEM to PKCS#1 PEM
openssl pkcs8 -nocrypt -in ecdsa_p256_private.pem -traditional -out ecdsa_p256_pk1_private.pem

### Convert RSA private key from PKCS#8 PEM to PKCS#1 DER
openssl pkey -in ecdsa_p256_private.pem -outform DER -out ecdsa_p256_pk1_private.der

### Convert ECDSA private key from PKCS#1 PEM to PKCS#8 PEM
openssl pkcs8 -nocrypt -in ecdsa_p256_pk1_private.pem -topk8 -out ecdsa_p256_private.pem

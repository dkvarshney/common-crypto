## Common Crypto
- Basic crypto CLI

Sample Commands, Please run the corresponding 'help' command for options.

###  RSA Commands
    Command Help:
    java -jar common-crypto.jar rsa help

    Wrap the data:
    java -jar common-crypto.jar rsa wrap
    > java -jar common-crypto.jar rsa wrap -wrappingkey=my-public-wrapping.key -material=my-key.key -wrapalgo=RSA_OAEP_SHA256 -output=my-wrapped-key.key
   
    Un-wrap the data:
    java -jar common-crypto.jar rsa unwrap
    > java -jar common-crypto.jar rsa unwrap -unwrappingkey=my-public-wrapping.key -material=my-key.key -wrapalgo=RSA_OAEP_SHA256 -output=my-unwrapped-key.key
   
    Generate RSA KeyPair:
    java -jar common-crypto.jar rsa generate
    > java -jar common-crypto.jar rsa generate -keysize=1024 -privatekey=private.key -publickey=public.key
   

### AES Commands
    Command Help:
    java -jar common-crypto.jar aes help

    Generate AES key:
    java -jar common-crypto.jar aes generate
    > java -jar common-crypto.jar aes generate -keysize=256 -output=aes.key 
  
... more commands to be added.

### Other openssl commands
    - Generate RSA private key:
    openssl genrsa -out private-key.pem 2048
    
    - Generate RSA public key from private key:
    openssl rsa -in private-key.pem -pubout > public-key.pem

    - Generate AES key:
    openssl rand 32 > aes-key.key

    - Convert RSA private key from PEM to PKCS#8 format:
    openssl pkcs8 -topk8 -inform PEM -outform DER -in private-key.pem -out private-key.der -nocrypt


## Command to decode the Base64 encoded ciphertext
base64 -d -i encodedcipher.txt -o ciphertext.txt

## Command to decrypt decoded ciphertext using AES and key (passphrase) 
openssl aes-128-ecb -d -in ciphertext.txt -k crypto -a -out message.txt
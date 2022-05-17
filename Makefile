decrypto-pro: decrypto-pro.c
	gcc -o decrypto-pro decrypto-pro.c /usr/lib/`arch`-linux-gnu/engines-1.1/gost.so -lssl -lcrypto

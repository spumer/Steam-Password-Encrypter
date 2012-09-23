#include <gmp.h> // работа с большими числами
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // for uint8_t
#include <time.h> // для генерации псевдослучайных чисел

// кодирование с помощью base64
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// Определяет позицию символа А в строке IN
//#define INDEX_OF(A, IN) (strchr(IN, A) - IN)

void pkcs1pad2(const char *data, int keysize, mpz_t *to);
char *base64(const uint8_t *input, size_t length);
//char *hex_decode(char *input);
size_t hexdecode(char *s, uint8_t **o);

int main(int argc, char **argv) {
	mpz_t bn_modulus;
	mpz_t bn_exponent;
	mpz_t bn_pkcs;
	
	mpz_init_set_str(bn_modulus, argv[1], 16);
	mpz_init_set_str(bn_exponent, "010001", 16);
	mpz_init(bn_pkcs);
	// Convert string to bigint
	pkcs1pad2(argv[2], (mpz_sizeinbase(bn_modulus, 2)+7)>>3, &bn_pkcs);
	mpz_powm(bn_pkcs, bn_pkcs, bn_exponent, bn_modulus);
	char *b1 = mpz_get_str(NULL, 16, bn_pkcs);
	uint8_t *b2;
	size_t b2_len = hexdecode(b1, &b2);	
	
	free(b1); // deallocate HEX string
	printf("%s", b1 = base64(b2, b2_len) );
	free(b2); // deallocate hex decoded string
	free(b1); // deallocate base64 string
	
	mpz_clear(bn_pkcs);
	mpz_clear(bn_modulus);
	mpz_clear(bn_exponent);	
	return 0;
}

void pkcs1pad2(const char *data, int keysize, mpz_t *to)
{
	// Переводим строку символов в массив
	unsigned char *buffer = (unsigned char *)malloc(keysize*sizeof(unsigned char));
	int len = strlen(data) - 1;
	int abs_len = keysize;
	while(len >=0 && keysize > 0)
		buffer[--keysize] = (unsigned char)data[len--];
	buffer[--keysize] = 0;
	srand( time(NULL) );
	while(keysize > 1)
		buffer[--keysize] = (rand() % 254) + 1;
	buffer[--keysize] = 2;
	
	// Импортируем массив как вид записи большого числа.
	mpz_import(*to, abs_len, 1, sizeof(unsigned char), 0, 0, buffer);
	free(buffer);
}
// Thx Ripper for this function
size_t hexdecode(char *s, uint8_t **o) {
    size_t blen = strlen(s) / 2;
    uint8_t *byr = malloc(blen);
    size_t i;
	for(i=0; i < blen; i++) {
        sscanf(s+i*2, "%2hhx", byr+i);
    }
    *o = byr;
    return blen;
}

char *base64(const uint8_t *input, size_t length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;
	
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);
	
	char *buff = (char *)malloc(bptr->length+1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = '\0';
	
	BIO_free_all(b64);
	
	return buff;
}

/*
char *hex_decode(char *input)
{
	unsigned int i = 0, len = strlen(input);
	const char *source = "0123456789abcdef";
	char *buffer = (char *)malloc(len+1); buffer[0] = '\0';
	do {
		sprintf(buffer, "%s%c", buffer, (int)((((INDEX_OF(input[i++], source)) << 4) & 0xf0) | (INDEX_OF(input[i++], source) & 0xf)) );
		//$output += String.fromCharCode((($hex.indexOf($input.charAt($i++)) << 4) & 0xf0) | ($hex.indexOf($input.charAt($i++)) & 0xf));
	}while(i < len);
	return buffer;
}*/
//============================================================================
// Name        : sslUtils.cpp
// Description : This class is inspired by the openssl wiki page.
//============================================================================

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"
#include <iostream>


BIO *bio_err = 0;
BIO *new_socket;

//Array for key and IV. This will be sent over SSL
unsigned char keys[48];
//Array for the key, 256 bits
unsigned char key[32];
//Array for the IV, 128 bits
unsigned char iv[16];


int berr_exit(const char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

//Password for the certificate of server and client
int password_cs(char *buf,int num, int rwflag,void *userdata){
	char *pass = "IK2206";
    if(num < strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

/*===========================Implement the four functions below============================================*/

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
	SSL *ssl;
	SSL_CTX *ctx;

	//Necessary library and crypto algorithms
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	EVP_add_cipher(EVP_aes_256_cbc());
	SSLeay_add_ssl_algorithms();

	//If the role is server
	if(role == 0) {
		printf("Hey, this is server\n");
		//Create a new SSL context object, the blueprint.
		ctx = SSL_CTX_new(SSLv23_server_method());

		//Set the verify for ctx of the peer certificate to be mode.
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		//Specifying the path to the root certificate
		SSL_CTX_load_verify_locations(ctx, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL);

		//If the server certificate is less than 0 return an error.
		if(SSL_CTX_use_certificate_file(ctx,"/home/cdev/SSLCerts/srv.pem", SSL_FILETYPE_PEM) < 0) {
			berr_exit("Certificate file cannot be accessed");
		}

		//If the server private key is less than 0 return an error.
		if(SSL_CTX_use_PrivateKey_file(ctx,"/home/cdev/SSLCerts/srv.key",SSL_FILETYPE_PEM) < 0) {
			berr_exit("Key file cannot be accessed");
		}

		//Public and private keys need to match, if not return false.
		if(!SSL_CTX_check_private_key(ctx)) {
			berr_exit("No matched private key");
		}

		//Authenticate the files with the correct password
		SSL_CTX_set_default_passwd_cb(ctx,password_cs);

		//Creating a new SSL structure loading the trusted certificate that was stored in ctx
		ssl = SSL_new(ctx);

		//Returns a socket bio using contChannel and close_flag
		new_socket = BIO_new_socket(contChannel, BIO_NOCLOSE);

		//SSL object will Read/Write from/to the same socket
		SSL_set_bio(ssl, new_socket, new_socket);

		//SSL handshake
		SSL_accept(ssl);

		//Check if the certificate is not X509, return error message
		if(SSL_get_verify_result(ssl) != X509_V_OK) {
			berr_exit("Verification failed!");
		}

		//Store the peer certificate
		X509 *peer;
		//Store the client ceritifcate in the peer variable
		peer = SSL_get_peer_certificate(ssl);

		//Store the common name from the peer certificate
		char peerCn[256];

		//Get the common name from the client certificate
		X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peerCn, 256);

		//Verify if the common names are known. If not, end the process.
		if(strcasecmp(peerCn,"TP Client nahida@kth.se amandatf@kth.se") != 0) {
			printf(peerCn);
			berr_exit(peerCn);
		}

		//Store the issuer name from the peer certificate
		char *peer_issuer = X509_NAME_oneline(X509_get_issuer_name(peer), NULL, 0);
		//Cast to a string
		std::string issuer = peer_issuer;

		//Verify if the is signed by rootCA. If not, end the process.
		if(issuer.find("TP CA nahida@kth.se amandatf@kth.se") == std::string::npos) {
			printf("issuer %s", issuer);
			berr_exit(peer_issuer);
		}

		//Free the peer
		X509_free(peer);
	} else {
		printf("Hey, this is client\n");
		//Create a new SSL context object, the blueprint.
		ctx = SSL_CTX_new(SSLv23_client_method());

		//Set the verify for ctx of the peer certificate to be mode.
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		//Specifying the path to the root certificate
		SSL_CTX_load_verify_locations(ctx, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL);

		//If the server certificate is less than 0 return an error.
		if(SSL_CTX_use_certificate_file(ctx,"/home/cdev/SSLCerts/cli.pem", SSL_FILETYPE_PEM) < 0) {
			berr_exit("Certificate file cannot be accessed");
		}

		//If the server private key is less than 0 return an error.
		if(SSL_CTX_use_PrivateKey_file(ctx,"/home/cdev/SSLCerts/cli.key",SSL_FILETYPE_PEM) < 0) {
			berr_exit("Key file cannot be accessed");
		}

		//Public and private keys need to match, if not return false.
		if(!SSL_CTX_check_private_key(ctx)) {
			berr_exit("No matched private key");
		}

		//Authenticate the files with the correct password
		SSL_CTX_set_default_passwd_cb(ctx,password_cs);

		//Creating a new SSL structure loading the trusted certificate that was stored in ctx
		ssl = SSL_new(ctx);

		//Returns a socket bio using contChannel and close_flag
		new_socket = BIO_new_socket(contChannel, BIO_NOCLOSE);

		//SSL object will Read/Write from/to the same socket
		SSL_set_bio(ssl, new_socket, new_socket);

		//SSL handshake
		SSL_connect(ssl);

		//Check if the certificate is not X509, return error message
		if(SSL_get_verify_result(ssl) != X509_V_OK) {
			berr_exit("Verification failed!");
		}

		//Store the peer certificate
		X509 *peer;
		//Store the server ceritifcate in the peer variable
		peer = SSL_get_peer_certificate(ssl);

		//Store the common name from the peer certificate
		char peerCn[256];

		//Get the common name from the client certificate
		X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peerCn, 256);

		//Verify if the common names are known. If not, end the process.
		if(strcasecmp(peerCn,"TP Server nahida@kth.se amandatf@kth.se") != 0) {
			printf("cn %s", peerCn);
			berr_exit(peerCn);
		}

		//Store the issuer name from the peer certificate
		char *peer_issuer = X509_NAME_oneline(X509_get_issuer_name(peer), NULL, 0);
		//Cast to a string
		std::string issuer = peer_issuer;

		//Verify if the is signed by rootCA. If not, end the process.
		if(issuer.find("TP CA nahida@kth.se amandatf@kth.se") == std::string::npos) {
			printf("issuer %s", issuer);
			berr_exit(peer_issuer);
		}

		//Free the peer
		X509_free(peer);
	}
	return ssl;
}

void dataChannelKeyExchange(int role, SSL *ssl) {

	//Generate a random key
	srand (time(NULL));

	if(role == 0) {

		//Choose 32 random number from 1 to 256 for the key
		int i;
		for(i = 0; i < 32; i++) {
			key[i] += rand() % 256 + 1;
		}

		//Choose 16 random number from 1 to 256 for the IV
		int j;
		for(j = 0; j < 16; j++) {
			iv[j] += rand() % 256 + 1;
		}

		//Store both the key and the IV into an array.
		int c;
		for(c = 0; c < 32; c++) {
			keys[c] = key[c];
		}
		int d;
		int e = 0;
		for(d = 32; d < 48; d++) {
			keys[d] = iv[e];
			e++;
		}

		//SSL_write writes n bytes(48) from the buffer keys which has the key and the IV, into the ssl connection.
		SSL_write(ssl, keys, 48);
	} else {

		//SSL_read reads n bytes(48) into the buffer keys which has the key and the IV, from the ssl connection.
		int x = SSL_read(ssl, keys, 48);
		if(x != 48) {
			berr_exit("Unsuccessfull to read random numbers\n");
		}

		//Seperate the keys array into the key and IV arrays.
		int i;
		for(i = 0; i < 32; i++) {
			key[i] = keys[i];
		}
		int j;
		int e = 0;
		for(j = 32; j < 48; j++) {
			iv[e] = keys[j];
			e++;
		}
	}
}

//Error handler for encryption and decryption
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

//Error handler to warn if the initial message fail during the decryption
void handleErrorsForInitMsg(void)
{
  ERR_print_errors_fp(stderr);
}

int encrypt(unsigned char *plainText, int plainTextLen, unsigned char *cipherText) {

	EVP_CIPHER_CTX *ctx;
	//The length of the read data
	int length = 0;
	//The length of the encrypted data
	int ciphertext_len = 0;

	//Initialize and create a cipher ctx object. If fails execute the error function
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}

	//Sets up cipher ctx for encryption with AES-256 cipher type, using symmetric key and IV.
	if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),NULL, key, iv)) {
		handleErrors();
	}

	//Encrypts the plain text and store the encrypted text into the ciphertext. Length variables stores the number of written bytes
	if(!EVP_EncryptUpdate(ctx, cipherText, &length, plainText, plainTextLen)) {
		handleErrors();
	}

	//Store the length of encrypted data from the length vairbale
	ciphertext_len = length;

	//Encrypt the remaining data. Length variables stores the number of written bytes
	if(!EVP_EncryptFinal_ex(ctx, cipherText + length, &length)) {
		handleErrors();
	}
	//Add the remaining number of byte to the total length
	ciphertext_len += length;

	//Free the ctx
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *cipherText, int cipherTextLen, unsigned char *plainText) {

	EVP_CIPHER_CTX *ctx;
	//The length of the read data
	int length = 0;
	//The length of the decrypted data
	int plaintext_len = 0;

	//Initialize and create a cipher ctx object. If fails execute the error function
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}

	//Sets up cipher ctx for decryption with AES-256 cipher type, using symmetric key and IV.
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(),NULL, key, iv)) {
		handleErrors();
	}

	//Decrypts the cipher text and store the decrypted text into the plainText. Length variables stores the number of written bytes
	if(!EVP_DecryptUpdate(ctx, plainText, &length, cipherText, cipherTextLen)) {
		handleErrors();
	}

	//Store the length of encrypted data from the length vairbale
	plaintext_len = length;

	//Decrypt the remaining data. Length variables stores the number of written bytes
	if(!EVP_DecryptFinal_ex(ctx, plainText + length, &length)) {
		handleErrorsForInitMsg();
	}

	//Add the remaining number of byte to the total length
	plaintext_len += length;

	//Free the ctx
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


#include "crypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <esp_log.h>
#include <aes/esp_aes.h>

#include "serial_io.h"
#include "lownet.h"

void crypt_decrypt(const lownet_secure_frame_t* cipher, lownet_secure_frame_t* plain)
{
    printf("crypt_DEcrypt\n");

    lownet_key_t* key = lownet_get_key();

    // Initialize the AES context
    esp_aes_context aes;
    esp_aes_init(&aes);

    // Set the AES encryption key using the key stored in net_system
    if (esp_aes_setkey(&aes, key->bytes, key->size * 8) != 0) {
        printf("Failed to set AES encryption key\n");
        esp_aes_free(&aes);
        return;
    }

    // Use the initialization vector (IV) from the cipher frame
    unsigned char iv[16];
    memcpy(iv, cipher->ivt, sizeof(iv));

    // Prepare the encrypted data to be decrypted
    uint8_t to_decrypt[LOWNET_ENCRYPTED_SIZE];
    memcpy(to_decrypt, &cipher->protocol, LOWNET_ENCRYPTED_SIZE);

    // Decrypt the data using AES in CBC mode
    if (esp_aes_crypt_cbc(&aes, ESP_AES_DECRYPT, LOWNET_ENCRYPTED_SIZE, iv, to_decrypt, (unsigned char*)&plain->protocol) != 0) {
        serial_write_line("AES decryption failed");
        esp_aes_free(&aes);
        return;
    }

    // Copy over the rest of the unencrypted parts (IVT, magic, etc.)
    memcpy(plain->magic, cipher->magic, sizeof(cipher->magic));
    memcpy(plain->ivt, cipher->ivt, sizeof(cipher->ivt));
    plain->source = cipher->source;
    plain->destination = cipher->destination;

    // Free the AES context
    esp_aes_free(&aes);
}


void crypt_encrypt(const lownet_secure_frame_t* plain, lownet_secure_frame_t* cipher)
{
    printf("crypt_encrypt\n");

    lownet_key_t* key = lownet_get_key();

    esp_aes_context aes;
    esp_aes_init(&aes);

    // Set the AES encryption key using the key stored in net_system
    if (esp_aes_setkey(&aes, key->bytes, key->size * 8) != 0) {
        printf("Failed to set AES encryption key\n");
        esp_aes_free(&aes);
        return;
    }

    // AES CBC requires an initialization vector (IV), here we use plain.ivt as the IV
    unsigned char iv[16]; 
    memcpy(iv, plain->ivt, sizeof(iv));

    // AES works on blocks of data, so ensure the encrypted portion is aligned.
    uint8_t to_encrypt[LOWNET_ENCRYPTED_SIZE];
    memcpy(to_encrypt, &plain->protocol, LOWNET_ENCRYPTED_SIZE);

    // Encrypt the data in CBC mode
    if (esp_aes_crypt_cbc(&aes, ESP_AES_ENCRYPT, LOWNET_ENCRYPTED_SIZE, iv, to_encrypt, (unsigned char*)&cipher->protocol) != 0) {
        printf("AES encryption failed\n");
        esp_aes_free(&aes);
        return;
    }

    // Copy over the rest of the unencrypted parts (IVT, magic, etc.)
    memcpy(cipher->magic, plain->magic, sizeof(plain->magic));
    memcpy(cipher->ivt, plain->ivt, sizeof(plain->ivt));
    cipher->source = plain->source;
    cipher->destination = plain->destination;

    // Free the AES context
    esp_aes_free(&aes);
}

// Usage: crypt_command(KEY)
// Pre:   KEY is a valid AES key or NULL
// Post:  If key == NULL encryption has been disabled
//        Else KEY has been set as the encryption key to use for
//        lownet communication.
void crypt_setkey_command(char* args) {
    // Initialize the AES key structure
    lownet_key_t aes_key;
    
    // Allocate memory for a 32-byte AES key
    aes_key.size = 32;  // Assuming LOWNET_KEY_SIZE_AES is 32 bytes
    aes_key.bytes = (uint8_t*)malloc(aes_key.size);
    
    if (aes_key.bytes == NULL) {
        // Memory allocation failed
        serial_write_line("Memory allocation for AES key failed");
        return;
    }

    if (args == NULL || strlen(args) == 0) {
        // Disable encryption by passing NULL
        lownet_set_key(NULL);
        serial_write_line("Encryption disabled");
        free(aes_key.bytes);  // Free the allocated memory
        return;
    }


    // Zero out the allocated memory (ensures padding with zeros)
    memset(aes_key.bytes, 0, aes_key.size);

    // Copy the user-provided key into the AES key, padding with zeros if necessary
    strncpy((char*)aes_key.bytes, args, strlen(args));

    // Set the AES key using the lownet_set_key function
    lownet_set_key(&aes_key);

    esp_aes_context aes;
    esp_aes_init(&aes);
    if (esp_aes_setkey(&aes, aes_key.bytes, aes_key.size * 8) != 0) {
        serial_write_line("Failed to set AES decryption key");
        return;
    }

    serial_write_line("Encryption key set");

    // Free the allocated memory after setting the key
    free(aes_key.bytes);
}




void crypt_test_command(char* str)
{
    serial_write_line("crypt test");
	if (!str)
		return;
	if (!lownet_get_key())
		{
			serial_write_line("No encryption key set!");
			return;
		}

	// Encrypts and then decrypts a string, can be used to sanity check your
	// implementation.
	lownet_secure_frame_t plain;
	lownet_secure_frame_t cipher;
	lownet_secure_frame_t back;

	memset(&plain, 0, sizeof(lownet_secure_frame_t));
	memset(&cipher, 0, sizeof(lownet_secure_frame_t));
	memset(&back, 0, sizeof(lownet_secure_frame_t));

	*((uint32_t*) plain.ivt) = 123456789;
	strcpy((char*) plain.payload, str);

	crypt_encrypt(&plain, &cipher);
	crypt_decrypt(&cipher, &back);

	if (strlen((char*) back.payload) != strlen(str))
		ESP_LOGE("APP", "Length violation");
	else
		serial_write_line((char*) back.payload);
}

#include "crypt.h"

#include <stdlib.h>
#include <string.h>

#include <esp_log.h>
#include <aes/esp_aes.h>

#include "serial_io.h"
#include "lownet.h"

void crypt_decrypt(const lownet_secure_frame_t* cipher, lownet_secure_frame_t* plain)
{
	// ...
}

void crypt_encrypt(const lownet_secure_frame_t* plain, lownet_secure_frame_t* cipher)
{
	// Initialize the AES context
    esp_aes_context aes;
    esp_aes_init(&aes);

    // Set the AES encryption key (assumed to be a 256-bit key)
    if (esp_aes_setkey(&aes, (const unsigned char *)lownet_public_key, 256) != 0) {
        ESP_LOGE(TAG, "Failed to set AES encryption key");
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
        ESP_LOGE(TAG, "AES encryption failed");
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
void crypt_setkey_command(char* args)
{
	// ...
}

void crypt_test_command(char* str)
{
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

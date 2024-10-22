#include "command.h"
#include <stdio.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#include "esp_timer.h"

#define TIMEOUT_MS 10000  // 10 seconds timeout
#define MASTER_PUBLIC_KEY lownet_public_key  // The stored master public key


static uint8_t buffered_message[LOWNET_PAYLOAD_SIZE];  // To store the normal frame's payload
static cmd_signature_t signature_parts[2];  // To store both parts of the signature
static int signature_parts_received = 0;
static uint64_t last_received_time = 0;  // To handle timeouts
static uint64_t last_sequence_number = 0;

void command_init()
{
	// ...
}

// Utility function to calculate SHA-256 hash of the message
void sha256(const uint8_t *message, size_t len, uint8_t *output_hash) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  // 0 means SHA-256, not SHA-224
    mbedtls_sha256_update(&ctx, message, len);
    mbedtls_sha256_finish(&ctx, output_hash);
    mbedtls_sha256_free(&ctx);
}

// Function to decrypt the signature using the public key
void RSA(const uint8_t *signature, uint8_t *decrypted_signature) {
    int ret;
    
    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa;

    mbedtls_pk_init(&pk);
    
    // Load the public key
    if ((ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)MASTER_PUBLIC_KEY, strlen(MASTER_PUBLIC_KEY) + 1)) != 0) {
        printf("Failed to parse public key: -0x%04X\n", -ret);
        return NULL;
    }
    
    // Get the RSA context
    rsa = mbedtls_pk_rsa(pk);

    // Decrypt the signature
    size_t decrypted_len = sizeof(decrypted_signature);
    ret = mbedtls_rsa_public_decrypt(rsa, CMD_BLOCK_SIZE, full_signature, decrypted_signature, &decrypted_len, MBEDTLS_RSA_PKCS_V15);
    
    if (ret < 0) {
        printf("Failed to decrypt signature: -0x%04X\n", -ret);
        mbedtls_pk_free(&pk);
        return NULL;
    }
    
    // Cleanup
    mbedtls_pk_free(&pk);
}


void test_sha(){
    char letter_a = 'a';

    uint8_t hash[CMD_HASH_SIZE];
    sha256((const uint8_t*)&letter_a, 1, hash);
}

// Command receive function
void command_receive(const lownet_frame_t *frame) {
    uint8_t protocol = frame->protocol;
    // Handle normal unsigned frame (00)
    if ((protocol & 0b11000000) == 0){
        printf("Received an unsigned normal frame.\n");
        return;
    }
    // Handle normal signed frame (01)
    else if ((protocol & 0b11000000) == 0x40) {
        printf("Received normal frame, expecting signature frames.\n");

        // Save the message payload for later signature verification
        memcpy(buffered_message, frame->payload, frame->length);
        
        uint64_t sequence_number = 0;
        memcpy(sequence_number, frame->payload, sizeof(uint64_t));
        if (sequence_number <= last_sequence_number){
            printf("The sequence number %llu, is less or equal than the last sequence number %llu. Aborting.\n", (unsigned long long)sequence_number, (unsigned long long)last_sequence_number);
            return;
        }
        last_sequence_number = sequence_number;

        // Reset signature buffer
        memset(signature_parts, 0, sizeof(signature_parts));
        signature_parts_received = 0;

        // Record the timestamp
        last_received_time = esp_timer_get_time();
    }

    // Handle the first part of the signature frame (10)
    else if ((protocol & 0b11000000) == 0x80) {
        printf("Received first part of the signature frame.\n");
        if (signature_parts_received == 0) {
            memcpy(&signature_parts[0], frame->payload, sizeof(cmd_signature_t));
            signature_parts_received = 1;
        } else {
            printf("Unexpected signature frame order. Discarding.\n");
            return;
        }
    }

    // Handle the second part of the signature frame (11)
    else if ((protocol & 0b11000000) == 0xC0) {
        printf("Received second part of the signature frame.\n");
        if (signature_parts_received == 1) {
            memcpy(&signature_parts[1], frame->payload, sizeof(cmd_signature_t));
            signature_parts_received = 2;
        } else {
            printf("Unexpected signature frame order. Discarding.\n");
            return;
        }
    }

    // Check if we have received both parts of the signature
    if (signature_parts_received == 2) {
        printf("Received both parts of the signature. Verifying...\n");

        // Step 1: Calculate the hash of the buffered message
        uint8_t calculated_msg_hash[CMD_HASH_SIZE];
        sha256(buffered_message, sizeof(buffered_message), calculated_msg_hash);

        // Step 2: Verify the message hash matches
        if (memcmp(calculated_msg_hash, signature_parts[0].hash_msg, CMD_HASH_SIZE) != 0 || memcmp(calculated_msg_hash, signature_parts[1].hash_msg, CMD_HASH_SIZE) != 0) {
            printf("Message hash does not match. Invalid signature.\n");
            return;
        }

        // Step 3: Verify the public key hash matches
        uint8_t public_key_hash[CMD_HASH_SIZE];
        sha256((const uint8_t *)MASTER_PUBLIC_KEY, strlen(MASTER_PUBLIC_KEY), public_key_hash);
        if (memcmp(public_key_hash, signature_parts[0].hash_key, CMD_HASH_SIZE) != 0 || memcmp(public_key_hash, signature_parts[1].hash_key, CMD_HASH_SIZE) != 0) {
            printf("Public key hash does not match. Invalid signature.\n");
            return;
        }

        process_signature_triple();
    }

    // Check for timeout
    uint64_t current_time = esp_timer_get_time();
    if ((current_time - last_received_time) > TIMEOUT_MS * 1000) {
        printf("Timeout waiting for signature frames. Discarding message.\n");
        signature_parts_received = 0;  // Reset the state
    }
}

// executes the command that is in the buffered_message (the payload of the latest normal frame)
void execute_command(){
    uint8_t command = 0;
    memcpy(&command, buffered_message + sizeof(uint64_t), sizeof(uint8_t));

    if (command != 1 && command != 2){
        printf("The command isn't 1 (Time) nor 2 (Test), but instead it's: %d. Aborting.", command);
        return;
    }
    else if(command == 1){ // Time command
        printf("Time command");

        lownet_time_t time;
        memcpy(&time, buffered_message + 12, sizeof(lownet_time_t));

        lownet_set_time(&time);
    }else{ // Test command  

    }

}


void process_signature_triple(){
    printf("Processing the triple...");

    // Step 4: Reassemble the full signature (256 bytes)
    uint8_t full_signature[CMD_BLOCK_SIZE];
    memcpy(full_signature, signature_parts[0].sig_part, CMD_BLOCK_SIZE / 2);
    memcpy(full_signature + CMD_BLOCK_SIZE / 2, signature_parts[1].sig_part, CMD_BLOCK_SIZE / 2);

    // Step 5: Verify the RSA signature using the full signature and the message hash
    uint8_t decrypted_signature[CMD_BLOCK_SIZE];
    RSA(full_signature, decrypted_signature);
    // Check if the first 220 bytes are zero
    for (int i = 0; i < 220; i++) {
        if (decrypted_signature[i] != 0) {
            printf("Validation failed: first 220 bytes are not zero.\n");
            return;  // Return failure
        }
    }

    // Check if the next 4 bytes are 1
    for (int i = 220; i < 224; i++) {
        if (decrypted_signature[i] != 1) {
            printf("Validation failed: next 4 bytes are not all 1.\n");
            return;  // Return failure
        }
    }

    // Check if the next 32 bytes are equal to signature_parts[0].hash_msg
    if (memcmp(&decrypted_signature[224], signature_parts[0].hash_msg, CMD_HASH_SIZE) != 0 || memcmp(&decrypted_signature[224], signature_parts[1].hash_msg, CMD_HASH_SIZE) != 0) {
        printf("Validation failed: next 32 bytes are not equal to hash_msg.\n");
        return;  // Return failure
    }

    printf("Signature is valid. Message is authentic.\n");
    execute_command();
}

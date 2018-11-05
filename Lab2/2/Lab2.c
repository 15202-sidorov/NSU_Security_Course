#ifndef __RC5_BLOCK_SIPHER__
#define __RC5_BLOCK_SIPHER__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define RC5_INPUT_FILE_ARG_NO 	1
#define RC5_OUTPUT_FILE_ARG_NO	2

#define RC5_MAX(a,b) ({__typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b;})


/*
	RC5 block ciphering algorithm.
*/

#define RC5_BLOCK_T		uint64_t            // Block type.
#define RC5_W   		32 	            // Half the block size in BITS.
#define RC5_WORD_T 		uint32_t            // Word type.
#define RC5_B   		8	            // Length of the key in BYTES.
#define RC5_R   		16 	            // Amount of rounds.
#define RC5_C   		(RC5_B*8)/RC5_W     // Size of key in words.

#define RC5_P   		0xb7e15163	    // Magical constants for 32 bits word size.
#define RC5_Q   		0x9e3779b9


static RC5_WORD_T RC5_ROTL(RC5_WORD_T word, uint32_t n) {
	n %= RC5_W-1;
	return (word << n) | (word >> (RC5_W - n));
}

static RC5_WORD_T RC5_ROTR(RC5_WORD_T word, uint32_t n) {
	n %= RC5_W-1;
	return (word >> n) | (word << (RC5_W - n));
}


/*
	Algorithm initialization.
*/

RC5_WORD_T l[RC5_C] = {0}; 			// Key splitted in words.
RC5_WORD_T s[2*(RC5_R + 1)] = {0}; 	// Extended key.

static void rc5_split_key_in_words(uint8_t *key) {
	int8_t u = RC5_W / 8;
	l[RC5_C-1] = 0;
	for (int8_t i = RC5_B-1; i >= 0; i--) {
		l[i/u] = (l[i/u] << 8) + key[i];
	}
}

static void rc5_build_extended_keys() {
	s[0] = RC5_P;
	for (uint8_t i = 1; i < 2 * (RC5_R + 1); i++) {
		s[i] = s[i-1] + RC5_Q;
	}
}

static void rc5_mix_keys_up() {
	RC5_WORD_T g = 0;
	RC5_WORD_T h = 0;
	RC5_WORD_T i = 0;
	RC5_WORD_T j = 0;
	uint8_t N = 3 * RC5_MAX(RC5_C, 2*(RC5_R+1));

	for (uint8_t index = 0; index < N; index++) {
		g = s[i] = RC5_ROTL(s[i] + g + h, 3);
		h = l[j] = RC5_ROTL(l[j] + g + h, g + h);
		i = (i + 1) % (2 * (RC5_R + 1));
		j = (j + 1) % RC5_C;
	}
}

/*
	Algorithm application.
*/

void rc5_cipher_block(RC5_WORD_T *block, RC5_WORD_T *output_buffer) {

	RC5_WORD_T a = block[0] + s[0];
	RC5_WORD_T b = block[1] + s[1];

	for (int8_t i = 1; i <= RC5_R; i++) {
		a = RC5_ROTL((a ^ b), b) + s[2*i];
        b = RC5_ROTL((b ^ a), a) + s[2*i+1];
	}

	output_buffer[0] = a;
	output_buffer[1] = b;

	return;
}

void rc5_decipher_block(RC5_WORD_T *ciphered_block, RC5_WORD_T *output_buffer) {
	RC5_WORD_T a = ciphered_block[0];
	RC5_WORD_T b = ciphered_block[1];

	for (int8_t i = RC5_R; i > 0; i--) {
		b = RC5_ROTR(b - s[2*i+1], a) ^ a;
		a = RC5_ROTR(a - s[2*i],   b) ^ b;
	}

	output_buffer[1] = b - s[1];
	output_buffer[0] = a - s[0];

	return; 
}

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "Not enough arguments.\n");
		fprintf(stderr, "(1) - Input file.");
		fprintf(stderr, "(2) - Output file.");
		return 1;
	}

    uint64_t key = 0x45ff45ff45ff45ff;

    rc5_split_key_in_words((uint8_t *)&key);
	rc5_build_extended_keys();
	rc5_mix_keys_up();

	FILE *input_file  = fopen(argv[RC5_INPUT_FILE_ARG_NO], "rb");
	FILE *output_file = fopen(argv[RC5_OUTPUT_FILE_ARG_NO],"wb");

	if (NULL == input_file || NULL == output_file) {
		fprintf(stderr, "Could not open files.");
		return 1;
	}

	size_t bytes_read = 0;
	RC5_WORD_T input_block[2] = {0};
	RC5_WORD_T output_block[2] = {0};
	RC5_WORD_T encoded_block[2] = {0};
	while (1) {
		bytes_read = fread(input_block, sizeof(RC5_WORD_T), 2, input_file);
		if (0 == bytes_read) {
			break;
		}
		
		rc5_cipher_block(input_block, encoded_block);
		rc5_decipher_block(encoded_block, output_block);
		fwrite(output_block, sizeof(RC5_WORD_T), 2, output_file);
	}

	fclose(input_file);
	fclose(output_file);

	return 0;
}

#endif

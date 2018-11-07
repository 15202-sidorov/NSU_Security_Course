#ifndef __BMP_STEGANOGRAPHY__
#define __BMP_STEGANOGRAPHY__

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define BMP_SIGNATURE_T uint16_t
#define BMP_SIZE_T  	uint32_t
#define BMP_RESERVED_T  uint32_t
#define BMP_PADDING_T   uint32_t

#define BMPST_CHUNK_T   uint8_t

typedef struct {
	char *           file_path;
	BMP_SIGNATURE_T  signature;
	BMP_SIZE_T       size;
	BMP_RESERVED_T   reserved;
	BMP_PADDING_T    padding;		
} BMP_picture;

typedef struct {
	char *           file_path;
	uint32_t 		 size;
} BMPST_message;


typedef struct {
	char *           output_path;
	uint8_t          bits_per_byte;
	BMP_picture *    picture;
	BMPST_message *  message;
} BMPST_config;

static void change_least_significant_bits(uint8_t *byte, uint8_t bits_to_change, uint8_t mask) {
	*byte = ((*byte >> bits_to_change) << bits_to_change) | mask; 
}

static uint8_t get_least_significant_bits(const uint8_t *byte, uint8_t bits_to_get) {
	uint8_t mask = (0xff >> (sizeof(uint8_t) * 8 - bits_to_get));
	
	return mask & *byte; 
}

int bmp_read_picture(char *input_file_name, BMP_picture *output_picture) {
	FILE *input_file = fopen(input_file_name, "rb");
	size_t bytes_read = 0;

	if (NULL == input_file) {
		fprintf(stderr, "Could not read picture %s\n", input_file_name);
		return -1;
	}
	printf("Picture is opened.\n");

	printf("Reading picture properties...\n");

	bytes_read += sizeof(BMP_SIGNATURE_T) * fread(&output_picture->signature, sizeof(BMP_SIGNATURE_T), 1, input_file);
	bytes_read += sizeof(BMP_SIZE_T) 	  * fread(&output_picture->size,      sizeof(BMP_SIZE_T),      1, input_file);
	bytes_read += sizeof(BMP_RESERVED_T)  * fread(&output_picture->reserved,  sizeof(BMP_RESERVED_T),  1, input_file);
	bytes_read += sizeof(BMP_PADDING_T)   * fread(&output_picture->padding,   sizeof(BMP_PADDING_T),   1, input_file);

	printf("DONE.\n");

	printf("Signature: %d\n",       output_picture->signature);
	printf("File size: %d\n",       output_picture->size);
	printf("Reserved: %d\n",        output_picture->reserved);
	printf("Padding: %d\n",         output_picture->padding);
	printf("Infoheader size: %d\n", output_picture->padding - bytes_read);
	printf("Header size: %d\n",     bytes_read);

	fclose(input_file);

	return 0;
}

int bmpst_conceal_message(
	const BMPST_config *config, 
	const char *input_picture_file_name,
	const char *input_message_file_name,
	const char *output_picture_file_name
) {
	FILE *output_file = fopen(output_picture_file_name, "wb");
	if (NULL == output_file) {
		fprintf(stderr, "Could not open output file %s\n", output_picture_file_name);
		return -1;
	}

	FILE *container = fopen(input_picture_file_name, "rb");
	if (NULL == container) {
		fprintf(stderr, "Could not open container %s\n", input_picture_file_name);
		fclose(output_file);
		remove(config->output_path);
		return -1;
	}
	
	FILE *data_stream = fopen(input_message_file_name, "rb");
	if (NULL == data_stream) {
		fprintf(stderr, "Could not open message %s\n", input_message_file_name);
		fclose(output_file);
		fclose(container);
		remove(config->output_path);
		return -1;
	}

	size_t        bytes_read = 0;
	BMPST_CHUNK_T current_chunk = 0;
	uint8_t		  buffer_size = sizeof(BMPST_CHUNK_T)*8 / config->bits_per_byte;
	uint8_t       buffer[buffer_size];
	uint8_t 	  header_buffer[config->picture->padding];
	uint32_t      counter = 0;
	
	// Rewrite header without changes.
	fread (header_buffer, sizeof(uint8_t), config->picture->padding, container  );
	fwrite(header_buffer, sizeof(uint8_t), config->picture->padding, output_file);


	// Go through the data, and change least significant n bits of every 4 byte word.
	while(1) {
		bytes_read = fread(&current_chunk, sizeof(BMPST_CHUNK_T), 1, data_stream);
		if (0 == bytes_read) {
			break;
		}

		bytes_read = fread(buffer, sizeof(uint8_t), buffer_size, container);
		if (0 == bytes_read) {
			fprintf(stderr, "Too much data, could not inject.");
			fclose(output_file);
			fclose(container);
			fclose(data_stream);
			remove(config->output_path);
			return -1;
		}

		for (uint8_t i = 0; i < buffer_size; i++) {
			change_least_significant_bits(
				buffer + i, 
				config->bits_per_byte, 
				(current_chunk << i*config->bits_per_byte) >> (buffer_size - 1)*config->bits_per_byte
			);
		}
		fwrite(buffer, sizeof(uint8_t), buffer_size, output_file);
		counter++;
	}

	config->message->size = counter;

	// Write others parts of pictures.
	while(1) {
		bytes_read = fread(&current_chunk, sizeof(BMPST_CHUNK_T), 1, container);
		if (0 == bytes_read) {
			break;
		}
		fwrite(&current_chunk, sizeof(BMPST_CHUNK_T), 1, output_file);
	}


	fclose(output_file);
	fclose(container);
	fclose(data_stream);

	return 0;
}

int bmpst_decode_message(
	const BMPST_config *config,
	const char *input_container_file_name,
	const char *output_message_file_name
) {
	FILE *output_file = fopen(output_message_file_name, "wb");
	if (NULL == output_file) {
		fprintf(stderr, "Could not output file %s\n", output_message_file_name);
		return -1;
	}

	FILE *container   = fopen(input_container_file_name, "rb"); 
	if (NULL == container) {
		fprintf(stderr, "%s\n", "Could not open picture %s\n", input_container_file_name);
		fclose(output_file);
		remove(config->output_path);
		return -1;	
	}

	// Go through the data, and fetch n bits of every 4 byte word.
	size_t        bytes_read = 0;
	uint8_t		  buffer_size = sizeof(BMPST_CHUNK_T)*8 / config->bits_per_byte;
	BMPST_CHUNK_T current_chunk = 0;
	uint8_t       buffer[buffer_size];
	uint32_t	  counter = 0;

	fseek(container, config->picture->padding, SEEK_SET);

	while(counter < config->message->size) {
		bytes_read = fread(buffer, sizeof(uint8_t), buffer_size, container);
		if (0 == bytes_read) {
			break;
		}

		for (uint8_t i = 0; i < buffer_size; i++) {
			current_chunk <<= config->bits_per_byte;
			current_chunk |= get_least_significant_bits(buffer+i, config->bits_per_byte);
		}

		fwrite(&current_chunk, sizeof(BMPST_CHUNK_T), 1, output_file);
		counter++;
	}


	fclose(output_file);
	fclose(container);
}


int main(int argc, char **argv) {
	if (argc < 5) {
		fprintf(stderr, "Not enough arguments.\n");
		fprintf(stderr, "(1) - Picture container .BMP.\n");
		fprintf(stderr, "(2) - Message file to be concealed.\n");
		fprintf(stderr, "(3) - Encoded image file name.\n");
		fprintf(stderr, "(4) - Decoded image file name.\n");
		return 1;
	}

	BMP_picture   picture;
	BMPST_message message;

	printf("Reading picture...\n", argv[1]);
	if (-1 == bmp_read_picture(argv[1], &picture)) {
		return 1;
	}
	printf("Picture is read.\n");

	BMPST_config configuration = {
		.bits_per_byte = 2,
		.picture       = &picture,
		.message       = &message
	};

	printf("Concealing message...\n");
	if (-1 == bmpst_conceal_message(&configuration, argv[1], argv[2], argv[3])) {
		return 1;
	}
	printf("Message is concealed.\n");

	printf("Fetching message...\n");
	if (-1 == bmpst_decode_message(&configuration, argv[3], argv[4])) {
		return 1;
	}
	printf("Message is fetched successfully!\n");

	return 0;
}

#endif
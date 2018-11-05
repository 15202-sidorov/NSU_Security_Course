#ifndef __STREAM_SIPHER__
#define __STREAM_SIPHER__

#include <stdint.h>
#include <string.h>

// Generator config.
#define SEED 				0x100000000
#define A 				    0x19660d
#define B					0x1013904223
#define ENCODE_START_VALUE 	0

// Encoding config.
#define CHUNCK_T			uint8_t
#define KEY_T				uint64_t
#define LOG_STREAM 			stdout

// Command line input config.
#define COMMAND_ARG_NO		3
#define INPUT_FILE_ARG_NO	1
#define OUTPUT_FILE_ARG_NO 	2
#define ENCODE_COMAND		"encode"
#define DECODE_COMAND		"decode"
#define TEST_COMMAND		"test"
#define ENCODED_FILE_NAME	".tmp.encoded"

KEY_T generate_key(KEY_T previous_value) {
	return (A * previous_value + B) % SEED;
}

CHUNCK_T encode_chunck(CHUNCK_T value, KEY_T key) {
	return (CHUNCK_T)(value ^ key);
}

CHUNCK_T decode_chunck(CHUNCK_T encoded_value, KEY_T key) {
	return (CHUNCK_T)(encoded_value ^ key);
}

int code_file(
	const char *input_file_name, 
	const char *output_file_name, 
	CHUNCK_T (*code_chunck)(CHUNCK_T, KEY_T)
) {
	FILE *input_file = fopen(input_file_name, "rb");
	if (NULL == input_file) 
	{
		fprintf(stderr, "ERROR: Could not open files.");
		return -1;
	}

	FILE *output_file = fopen(output_file_name, "wb");
	if (NULL == output_file)
	{
		fprintf(stderr, "ERROR: Could not open files.");
		return -1;
	}

	CHUNCK_T input_chunck = 0;
	CHUNCK_T output_chunck = 0;
	KEY_T 	 current_key = generate_key(ENCODE_START_VALUE);
	size_t 	 bytes_read = sizeof(CHUNCK_T);
	
	while(1) {
		bytes_read = fread(&input_chunck, sizeof(CHUNCK_T), 1, input_file);
		if (bytes_read == 0) {
			break;
		}
		
		output_chunck = (*code_chunck)(input_chunck, current_key);
		fwrite(&output_chunck, sizeof(CHUNCK_T), 1, output_file);
		current_key = generate_key(current_key);
	}
	

	fclose(input_file);
	fclose(output_file);
	
	return 0;
}

void encode_file(const char *input_file_name, const char *output_file_name) {
	fprintf(LOG_STREAM, "%s\n", "Start file encoding.");
	fprintf(LOG_STREAM, "%s >> %s\n", input_file_name, output_file_name);

	if (-1 == code_file(input_file_name, output_file_name, encode_chunck)) {
		fprintf(LOG_STREAM, "%s\n", "Could not encode file.");
		return;
	}

	fprintf(LOG_STREAM, "%s\n", "Encoding successful.");
	fprintf(LOG_STREAM, "%s %s %s\n", input_file_name, "is successfuly incoded into", output_file_name);
	
	return;
}

void decode_file(const char *input_file_name, const char *output_file_name)
{
	fprintf(LOG_STREAM, "%s\n", "Start file decoding.");
	fprintf(LOG_STREAM, "%s >> %s\n", input_file_name, output_file_name);

	if (-1 == code_file(input_file_name, output_file_name, decode_chunck)) {
		fprintf(LOG_STREAM, "%s\n","Could not decode file.");
		return;
	}

	fprintf(LOG_STREAM, "%s\n", "Decoding successful.");
	fprintf(LOG_STREAM, "%s %s %s\n", input_file_name, "is successfuly decoded into", output_file_name);
	
	return;
}

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, "Not enough arguments.\n");
		fprintf(stderr, "(1) - Input file.");
		fprintf(stderr, "(2) - Output file.");
		fprintf(stderr, "(3) - encode/decode/test commands.");
		return 1;
	}

	if (0 == strcmp(argv[COMMAND_ARG_NO],DECODE_COMAND)) {
		decode_file(argv[INPUT_FILE_ARG_NO], argv[OUTPUT_FILE_ARG_NO]);
	}
	else if (0 == strcmp(argv[COMMAND_ARG_NO],ENCODE_COMAND)) {
		encode_file(argv[INPUT_FILE_ARG_NO], argv[OUTPUT_FILE_ARG_NO]);
	}
	else if (0 == strcmp(argv[COMMAND_ARG_NO],TEST_COMMAND)) {
		encode_file(argv[INPUT_FILE_ARG_NO], ENCODED_FILE_NAME);
		decode_file(ENCODED_FILE_NAME, argv[OUTPUT_FILE_ARG_NO]);
		remove(ENCODED_FILE_NAME);
	}

	return 0;
}

#endif
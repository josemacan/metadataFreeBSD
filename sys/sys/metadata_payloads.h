#ifndef METADATA_PAYLOADS_H_
#define	METADATA_PAYLOADS_H_

#define PAYLOADS_TOTAL 3 			// IMPORTANT: update this number each time you add or remove a Payload_X struct
#define BINPAYLOAD_MAXSIZE 2048

#define PAYLOAD_A_ARGS_COUNT 4		// For security, check this number when parsing this type of payload

typedef struct {
	int num_a;
	int num_b;
	char caracter;
    size_t int_size;
} Payload_A;

#define PAYLOAD_B_ARGS_COUNT 4			// For security

typedef struct {
	int num_a;
	char char_B1;
	char char_B2;
    size_t char_size;
} Payload_B;

#define PAYLOAD_BINARY_ARGS_COUNT 3			// For security

typedef struct {
	long bin_data_size; 						  // Size in bytes of the raw binary data
	size_t charArray_bin_size;					  // Count of characters of the binary_data as string
	char binary_data[BINPAYLOAD_MAXSIZE];         // Binary data as a string 
} Payload_Binary;

typedef struct {
	int p_function_number;         // Function number associated to the payload                 
    size_t p_size;                 // Size of the payload
} Payload_Hdr;


typedef struct {
    int m_number_payloads;          // Total number of different payloads in the section (num of entries in the payload header table)               
    size_t ph_size;                 // Size of an entry in the payload header table
} Metadata_Hdr;



#endif /* METADATA_PAYLOADS_H_ */
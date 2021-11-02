#ifndef METADATA_PAYLOADS_H_
#define	METADATA_PAYLOADS_H_

typedef struct {
	int num_a;
	int num_b;
	char caracter;
    size_t int_size;
} Payload_A;

typedef struct {
	int num_a;
	char char_B1;
	char char_B2;
    size_t char_size;
} Payload_B;

typedef struct {
	int p_function_number;         // Function number associated to the payload                 
    size_t p_size;                 // Size of the payload
} Payload_Hdr;


typedef struct {
    int m_number_payloads;          // Total number of different payloads in the section (num of entries in the payload header table)               
    size_t ph_size;                 // Size of an entry in the payload header table
} Metadata_Hdr;

#endif /* METADATA_PAYLOADS_H_ */
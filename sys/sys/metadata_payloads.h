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
	int ph_function_number;         // Function number associated to the payload
	off_t ph_offset;                // Offset to the payload                 
    size_t ph_size;                 // Size of the payload
    void *ph_payload;               // Payload address
} Payload_Hdr;

typedef struct {
    Payload_Hdr payloadhdr_node;
} PayloadHdr_List;

typedef struct {
	off_t m_ph_offset;              // Offset to the payload header table
    int m_number_payloads;          // Total number of different payloads in the section (num of entries in the payload header table)               
    size_t ph_size;                 // Size of an entry in the payload header table
    Payload_Hdr *payloadhdr_list;   // Payload headers list
} Metadata_Hdr;

#endif /* METADATA_PAYLOADS_H_ */
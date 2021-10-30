#ifndef METADATA_ELF_READER_H
#define METADATA_ELF_READER_H

#include <machine/elf.h>
#include <sys/param.h>
#include <sys/imgact_elf.h>
#include <sys/proc.h>

#define SECCION_BUSCADA ".metadata"

// NUM OF FUNCTION DIGITS 
#define FUNCTION_NDIGITS 4 // From 0 to 

// FUNCTION LOOKUP TABLE
enum metadata_function_num {
	UND, // 0
	COM, // 1
	IMG, // 2 
	SCH, // 3 
	PNA, // 4
};

// PAYLOAD STRUCTS

typedef struct {
	int num_a;
	int num_b;
	char caracter;
} Payload;

// ********* FUNCTIONS ********* 

void* getMetadataSectionPayload(const Elf_Ehdr *, struct image_params *, int *, size_t *);
//char* getMetadataSectionPayload(const Elf_Ehdr *, struct image_params *, int *);
void copyMetadataToProc(void *, int, size_t, struct thread *);
//int copyMetadataToProc(char *, struct thread *);
char* getPayloadPerFunction(struct thread *, int , int *);

void decodeMetadataSection(struct thread *);
#endif
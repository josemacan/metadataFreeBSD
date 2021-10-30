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

// Functions
void* getMetadataSectionPayload(const Elf_Ehdr *, struct image_params *, int *, size_t *);
//char* getMetadataSectionPayload(const Elf_Ehdr *, struct image_params *, int *);
int copyMetadataToProc(char *, struct thread *);
char* getPayloadPerFunction(struct thread *, int , int *);
#endif
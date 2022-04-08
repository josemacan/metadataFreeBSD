#ifndef METADATA_ELF_READER_H
#define METADATA_ELF_READER_H

#include <machine/elf.h>
#include <sys/param.h>
#include <sys/imgact_elf.h>
#include <sys/proc.h>
#include <sys/metadata_payloads.h>


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

// ********* FUNCTIONS ********* 

void* getMetadataSectionPayload(const Elf_Ehdr *, struct image_params *, int *, size_t *);
void copyMetadataToProc(void *, int, size_t, struct thread *);
void decodeMetadataSection(struct thread *);

// ********* PAYLOAD FUNCTIONS ********* 

void payload_A_func(void*, Payload_A* );
void payload_B_func(void*, Payload_B* );
void payload_Binary_func(void*, Payload_Binary* );

#endif
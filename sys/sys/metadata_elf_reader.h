#ifndef METADATA_ELF_READER_H
#define METADATA_ELF_READER_H

#include <machine/elf.h>
#include <sys/param.h>
#include <sys/imgact_elf.h>
#include <sys/proc.h>

#define SECCION_BUSCADA ".metadata"

// Functions
char* getMetadataSectionPayload(const Elf_Ehdr *, struct image_params *, int *);
int copyMetadataToProc(char *, struct thread *);
#endif
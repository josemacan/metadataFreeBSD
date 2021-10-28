// Kernel libraries 

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

//#include "opt_capsicum.h"
//#include "opt_compat.h"
//#include "opt_gzio.h"

//#include <sys/capsicum.h>
//#include <sys/exec.h>
//#include <sys/gzio.h>

#include <sys/param.h>
#include <sys/fcntl.h>

#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/namei.h>
#include <sys/pioctl.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sf_buf.h>
#include <sys/smp.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/eventhandler.h>
#include <sys/user.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>

#include <machine/elf.h>
#include <machine/md_var.h>

#include <sys/metadata_elf_reader.h>


// Memory space for buffers and other retrieved data
static MALLOC_DEFINE(M_ELFHEADER, "Elf Header", "Memory for the elf header");  // @1: type (must start with 'M_') @2: shortdesc @3: longdesc 
static MALLOC_DEFINE(M_BUFFER, "buffer", "Memory for buffer" );                 // " " of type M_BUFFER
static MALLOC_DEFINE(M_SECTION, "section data", "Memory for section data" );              // " " of type M_SECTION
//MALLOC_DEFINE(M_METASECTIONDATA, "metadata section data", "Memory for metadata section data" );              // " " of type M_METASECTIONDATA

char* 
getMetadataSectionPayload(const Elf_Ehdr *hdr, struct image_params *imgp, int* return_flag){

    /////////////////
    log(LOG_INFO, "\n\t\t 1) ** getMetadataSectionPayload ** has been called\n");
    /////////////////

	
 	struct thread *td;
    Elf_Shdr *sectionheader_table;
	int flags_mallocELFRead = M_WAITOK | M_ZERO;
	int error;
	//char error_msg[] = "ERROR";
	

    /////////////////
    //log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Elf_Ehdr -- size of section header table entry: %u\n", hdr->e_shentsize);
    //log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Elf_Ehdr -- count of section header table entries: %u\n", hdr->e_shnum);
	//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Elf_Ehdr -- size of whole section header table: %u\n", (hdr->e_shentsize)*(hdr->e_shnum));
    /////////////////

    /////////////////////////////////////////////////////////////////////

	// 1) Memory allocation to store ELF section header table

	// Use M_TEMP allocated memory
	sectionheader_table = malloc((hdr->e_shentsize)*(hdr->e_shnum), M_ELFHEADER, flags_mallocELFRead );
	if(sectionheader_table == NULL){
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR IN MALLOC - sectionheader_table\n");
		goto fail;
	}

    // 2) Read ELF section header table

	// Lock to serialize the access to the file system

	vn_lock(imgp->vp, LK_EXCLUSIVE | LK_RETRY);

	// Read ELF file to sectionheader_table

	td = curthread;

	error = vn_rdwr(UIO_READ, imgp->vp, sectionheader_table, (hdr->e_shentsize)*(hdr->e_shnum), hdr->e_shoff,
		UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);
	if (error) {
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR vn_rdwr section header table %d\n", error);
        goto fail1;
    }


	//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Index of string section header in table %hu -- hex: 0x%x\n", hdr->e_shstrndx, hdr->e_shstrndx);   
	//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- size of strndx section in bytes: %zu\n", (size_t) sectionheader_table[hdr->e_shstrndx].sh_size); 

	// 3) Elements needed to iterate over each section of the ELF file.

	char* sh_str;
  	char* buff;

	buff = malloc(sectionheader_table[hdr->e_shstrndx].sh_size, M_BUFFER, flags_mallocELFRead);
  	if(buff == NULL){
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR IN MALLOC - buff\n");
    	goto fail1;
  	}

    // 4) Read buff

	error = vn_rdwr(UIO_READ, imgp->vp, buff, sectionheader_table[hdr->e_shstrndx].sh_size, sectionheader_table[hdr->e_shstrndx].sh_offset,
		UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);
	if (error) {
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR vn_rdwr buff %d\n", error);
		goto fail2;
	}

    // 5) Assign

	sh_str = buff;

	//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- sh_str = buff \n");

	// 6) Iterate over each section of the section header table

	int mm = 0;

	for(mm = 0; mm < hdr->e_shnum; mm++)
	{  // Compare the name of the actual section vs the desired (.metadata) section
		//log(LOG_INFO,"\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Section %s --\n", buff + sectionheader_table[mm].sh_name);
		if(strcmp(SECCION_BUSCADA, (buff + sectionheader_table[mm].sh_name)) == 0)
		{
			log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Seccion encontrada --\n");
			log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Seccion %s encontrada en offset 0x%lx y de tamanio %lu bytes--\n", 
					SECCION_BUSCADA, (off_t) sectionheader_table[mm].sh_offset, (size_t) sectionheader_table[mm].sh_size);
			
			log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // --- Desired section FOUND\n");
			
			break;
		}
	}

    // 7) Memory allocation to store string of the section

	char* sectiondata = malloc(sectionheader_table[mm].sh_size, M_SECTION, flags_mallocELFRead);
	if(sectiondata == NULL){
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR IN MALLOC - sectiondata\n");
    	goto fail2;
	}

	
    // 8) Check if the desired section (.metadata) was found in earlier iteration

	if (mm < hdr->e_shnum) {
		// 9) Init variables to section data
		off_t sectiondata_offset = 0;
		size_t sectiondata_size = 0;

		sectiondata_offset = sectionheader_table[mm].sh_offset;    // Points to the start of the desired section
		sectiondata_size = sectionheader_table[mm].sh_size;      // Size of the desired section

		// 10) Add end of string

		sectiondata[sectiondata_size] = '\0';    

		// 11) Read section data

		error = vn_rdwr(UIO_READ, imgp->vp, sectiondata, sectiondata_size, 
						sectiondata_offset, 
						UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);

		if (error) {
			log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR vn_rdwr sectiondata %d\n", error);
			goto fail3;
		}

		// 12) Print data of the section

		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- *** %s section data: *** \n%s\n", 
			SECCION_BUSCADA, sectiondata);

        // 13) Return sectiondata pointer

		*return_flag = 1;
        goto ret;
	} 
	else {
        // Section was not found, return NULL
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- *** SECTION NOT FOUND ***\n");
        *return_flag = 2;
		sectiondata = NULL;

        goto ret;
	}


	// Free allocated memory
fail3:
  	free(sectiondata, M_SECTION);
fail2:
    free(buff, M_BUFFER);    
fail1:
	free(sectionheader_table, M_ELFHEADER);
fail:
    // Unlock 
	VOP_UNLOCK(imgp->vp, 0);

	//strcpy(sectiondata, error_msg);
	*return_flag = -1;
    return NULL;
    //return error_msg;

ret:
	// Unlock 
	VOP_UNLOCK(imgp->vp, 0);

	// Free allocated memory 
	free(sectionheader_table, M_ELFHEADER);
	free(buff, M_BUFFER);
  	//free(sectiondata, M_SECTION);
	
    return sectiondata;

	// ************************ BORRAR ************************
	//return NULL;

}

int copyMetadataToProc(char *metadata, struct thread *td){
	int ret = 0;

	// ret -1 if error; else, num chars that would have been printed if the size were unlimited (not including final \0)
	ret = snprintf(td->td_proc->p_metadata, MAXHOSTNAMELEN, "%s", metadata);

	return ret;
}

char* getPayloadPerFunction(struct thread *td, int num_function, int* return_flag){ 

	if(num_function == UND){
		log(LOG_INFO, "\t\t 3) // getPayloadPerFunction() // LectorELF // -- ERROR - function number is 0 - INVALID\n");
		goto fail;
	}

	char metadataSectionData[MAXHOSTNAMELEN];
	//char returned_payloadstring[MAXHOSTNAMELEN];

	memcpy(metadataSectionData, td->td_proc->p_metadata, sizeof(td->td_proc->p_metadata));	// Copy metadata from proc struct

	//////////////////
		//log(LOG_INFO, "\t\t 3) // getPayloadPerFunction() // LectorELF // -- td->td_proc->p_metadata: %s\n", td->td_proc->p_metadata);
		log(LOG_INFO, "\t\t 3) // getPayloadPerFunction() // LectorELF // -- metadataSectionData: %s\n", metadataSectionData);
	//////////////////

	int len_func1 = FUNCTION_NDIGITS+1+1+1;

	char func1[len_func1];
	sprintf(func1, "[%d:",num_function);
	
	////////////////
	log(LOG_INFO, "\t\t 3) // getPayloadPerFunction() // LectorELF // -- func1: ");
	for(int zz = 0; zz < sizeof(func1); zz++){
		log(LOG_INFO, "%c", func1[zz]);
		}
	log(LOG_INFO, "\n");
	////////////////

		//log(LOG_INFO, "\t\t 3) // getPayloadPerFunction() // LectorELF // -- func1: %s\n", func1);
	//////////////////	

	goto ret;

fail:
	*return_flag = -1;
    return NULL;

ret: 
	*return_flag = 2;
	return NULL;

}
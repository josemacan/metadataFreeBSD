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
MALLOC_DEFINE(M_FUNC1_CHARP, "func1", "Memory for func1" );              // " " of type M_METASECTIONDATA

#define MAXBUFFER_PAYLOAD 1024
#define FUNC1CHARP_LEN 51

void* 
getMetadataSectionPayload(const Elf_Ehdr *hdr, struct image_params *imgp, int* return_flag, size_t* payload_size){

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

    // 7) Memory allocation to store data of the section

	void* sectiondata = malloc(sectionheader_table[mm].sh_size, M_SECTION, flags_mallocELFRead);
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
		
		//sectiondata[sectiondata_size] = '\0';    // ******************** BORRAR

		// 11) Read section data

		error = vn_rdwr(UIO_READ, imgp->vp, sectiondata, sectiondata_size, 
						sectiondata_offset, 
						UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);

		if (error) {
			log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR vn_rdwr sectiondata %d\n", error);
			goto fail3;
		}

		// 12) Print data of the section

		//////////////////////
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- *** %s section data: *** \n%p\n", 
			SECCION_BUSCADA, sectiondata);
		/////////////////////

        // 13) Return sectiondata pointer
		*payload_size = sectiondata_size;
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



void copyMetadataToProc(void *metadata_addr, int returned_flag, size_t payload_size, struct thread *td){

	/* * METADATA: proc struct metadata pointer points to returned address */
	//*td->td_proc->p_metadata_addr = *metadata_addr;
	td->td_proc->p_metadata_addr = metadata_addr;

	/* * METADATA: Assign metadata returned flag to proc struct */
	td->td_proc->p_metadata_section_flag = returned_flag;

	/* * METADATA: Assign metadata returned size to proc struct */
	td->td_proc->p_metadata_size = payload_size;
	
}

void decodeMetadataSection(struct thread *td){

	/////////////
		log(LOG_INFO, "\t\t 4) ** decodeMetadataSection() ** has been called\n");
	/////////////

	/* 1) Get Metadata_Hdr address using:
		- Start addr of Metadata_Hdr  = (td->td_proc->p_metadata_addr + td->td_proc->p_metadata_size) - sizeof(Metadata_Hdr)
		- End addr of Metadata_Hdr  = (td->td_proc->p_metadata_addr + td->td_proc->p_metadata_size)
	*/

	void* metadata_end_addr = (char *) (td->td_proc->p_metadata_addr) + td->td_proc->p_metadata_size;
	void* metadata_hdr_start_addr = (char *) (metadata_end_addr) - sizeof(Metadata_Hdr);
	
	/////////////
		log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // metadata_end_addr: %p - metadata_hdr_start_addr: %p \n", metadata_end_addr, metadata_hdr_start_addr);
	/////////////

	Metadata_Hdr metadata_header_decod;
	memcpy(&metadata_header_decod, metadata_hdr_start_addr, sizeof(Metadata_Hdr));

			////////////
			log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // Metadata_Hdr = metadata_header_decod //// m_ph_offset: %ld - m_number_payloads: %d - ph_size: %lu - *payloadhdr_list: %p\n", 
				metadata_header_decod.m_ph_offset, metadata_header_decod.m_number_payloads, metadata_header_decod.ph_size, metadata_header_decod.payloadhdr_list);
			////////////

	/* 2) Get Payload_Hdr address:
		- Start addr of Payload_Hdr  = Start of Metadata_Hdr addr - (Metadata_Hdr.m_number_payloads * Metadata_Hdr.ph_size)
		- End addr of Payload_Hdr  = Start of Metadata_Hdr addr
	*/
	
	size_t payload_headers_table_size = (metadata_header_decod.m_number_payloads) * (metadata_header_decod.ph_size);
	void* payload_hdrs_table_start_addr = (char *) (metadata_hdr_start_addr) - payload_headers_table_size;

	/////////////
		log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // payload_hdrs_table_start_addr: %p - payload_headers_table_size: %lu \n", payload_hdrs_table_start_addr, payload_headers_table_size);
	/////////////

	Payload_Hdr payload_header_decod;
	void* payhdr_addr = NULL;

	//Payload_A payload_decod;
	//void* payload_addr = NULL;
	//payload_addr = td->td_proc->p_metadata_addr;

	for(int k = 0; k < metadata_header_decod.m_number_payloads; k++){
		payhdr_addr = &(((Payload_Hdr *)payload_hdrs_table_start_addr)[k]);
		
			/////////////
				log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // payhdr_addr[%d]: %p\n", k, payhdr_addr);
			/////////////

		memcpy(&payload_header_decod, payhdr_addr, sizeof(Payload_Hdr));

			////////////
			log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // Payload_Hdr = payload_header_decod[%d] //// ph_function_number: %d - ph_offset: %ld - ph_size: %lu - *ph_payload: %p\n", 
				k, payload_header_decod.ph_function_number, payload_header_decod.ph_offset, payload_header_decod.ph_size, payload_header_decod.ph_payload);
			////////////

			/* 3) Get each Payload address:
				- Start addr of first Payload  = Start of metadata section
				- End addr of last Payload  = Start addr of Payload_Hdr
			*/		

			/////////////
				//log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // payload_addr: %p\n", payload_addr);
			/////////////	

			//payload_addr = (char *) payload_addr + payload_header_decod.ph_size;



	}


	/////////////
		log(LOG_INFO, "\t\t 4) ** decodeMetadataSection() ** EXIT\n");
	/////////////

}
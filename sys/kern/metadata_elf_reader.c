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

#define MAXBUFFER_PAYLOAD 1024
#define FUNC1CHARP_LEN 51


void payload_A_func(void* payload_addr, Payload_A* payloadA_decod){

	memcpy(payloadA_decod, payload_addr, sizeof(Payload_A));	

	////////////
		log(LOG_INFO, "\t\t\t 4) // decodeMetadataSection() // payload_A_func() // Payload_A = payloadA_decod //// num a: %d - num b: %d - caracter: %c - int_size: %lu\n", 
			payloadA_decod->num_a, payloadA_decod->num_b, payloadA_decod->caracter, payloadA_decod->int_size);
	////////////

}

void payload_B_func(void* payload_addr, Payload_B* payloadB_decod){ 

	memcpy(payloadB_decod, payload_addr, sizeof(Payload_B));	

	////////////
		log(LOG_INFO, "\t\t\t 4) // decodeMetadataSection() // payload_B_func() // Payload_B = payloadB_decod //// num a: %d - char_B1: %c - char_B2: %c - char_size: %lu\n", 
			payloadB_decod->num_a, payloadB_decod->char_B1, payloadB_decod->char_B2, payloadB_decod->char_size);
	////////////		
}


void payload_Binary_func(void* payload_addr, Payload_Binary* payloadBinary_decod){
	memcpy(payloadBinary_decod, payload_addr, sizeof(Payload_Binary));	

	log(LOG_INFO, "\t\t\t 4) // decodeMetadataSection() // payload_Binary_func() // Payload_Binary = payloadBinary_decod //// bin_data_size: %ld - charArray_bin_size: %zu\n", 
			payloadBinary_decod->bin_data_size, payloadBinary_decod->charArray_bin_size);

	//long data_size = payloadBinary_decod->bin_data_size;			// Extract raw binary data size in bytes

	char char_bin_data[BINPAYLOAD_MAXSIZE] = {0};		// Create a char array to save the string (bin data as char) in it
	memcpy(char_bin_data,  payloadBinary_decod->binary_data, BINPAYLOAD_MAXSIZE);	

	// Print the extracted string 

	log(LOG_INFO, "\t\t\t\t 4) // decodeMetadataSection() // payload_Binary_func() // char_bin_data: \n\t\t\t\t\t");

	for(int z = 0; z < BINPAYLOAD_MAXSIZE; z++){
		log(LOG_INFO, "%c", char_bin_data[z]);
	}

	
	char bytes_as_char[BINPAYLOAD_MAXSIZE][3] = {{0}};

	log(LOG_INFO, "\n\t\t\t\t 4) // decodeMetadataSection() // payload_Binary_func() // bytes_as_char: \n\t\t\t\t\t");

	for(int i = 0; i < payloadBinary_decod->bin_data_size; i = i + 1){
		bytes_as_char[i][0] = char_bin_data[2*i];
		bytes_as_char[i][1] = char_bin_data[(2*i)+1];
		bytes_as_char[i][2] = '\0';
		log(LOG_INFO,"%c%c ", bytes_as_char[i][0],bytes_as_char[i][1]);
	}

	uint8_t bin_data[BINPAYLOAD_MAXSIZE] = {0};
	int tmp_cast_value = 0;

	for(int m = 0; m < payloadBinary_decod->bin_data_size; m++){
		sscanf(bytes_as_char[m], "%x", &tmp_cast_value);
		bin_data[m] = (uint8_t) tmp_cast_value;
	}

	log(LOG_INFO, "\n\t\t\t\t 4) // decodeMetadataSection() // payload_Binary_func() // bin_data - Canonical hex: \n\t\t\t\t\t");


	for(int j = 0; j < payloadBinary_decod->bin_data_size; j++){
		log(LOG_INFO," %02X", bin_data[j]);
	}

	log(LOG_INFO, "\n\t\t\t\t 4) // decodeMetadataSection() // payload_Binary_func() // bin_data - ASCII read: \n\t\t\t\t\t");


	for(int p = 0; p < (payloadBinary_decod->bin_data_size); p++){
		if(bin_data[p] > 31 && bin_data[p] < 127){
			log(LOG_INFO,"%c", bin_data[p]);
		}
		else{
			log(LOG_INFO,".");
		}
	}

	log(LOG_INFO, "\n");

}


typedef void (*payload_A_func_wrapper)(void* payload_addr, Payload_A* payloadA_decod);
typedef void (*payload_B_func_wrapper)(void* payload_addr, Payload_B* payloadB_decod);
typedef void (*payload_Binary_func_wrapper)(void* payload_addr, Payload_Binary* payloadBinary_decod);


typedef void (*payload_func)(void); // array of function pointers to store each function matching a different payload struct. Definition and instantiation 
									// in metadata_elf_reader.c

payload_func payload_functions[PAYLOADS_TOTAL+1] = {NULL, (payload_func) payload_A_func, (payload_func) payload_B_func, (payload_func) payload_Binary_func};



void* 
getMetadataSectionPayload(const Elf_Ehdr *hdr, struct image_params *imgp, int* return_flag, size_t* payload_size){

    /////////////////
    log(LOG_INFO, "\n\t\t 1) ** getMetadataSectionPayload ** has been called\n");
    /////////////////

	
 	struct thread *td;
    Elf_Shdr *sectionheader_table;
	int flags_mallocELFRead = M_WAITOK | M_ZERO;
	int error = 0;
	
	// Asign current thread to td struct

    td = curthread; 

    /////////////////
    //log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Elf_Ehdr -- size of section header table entry: %u\n", hdr->e_shentsize);
    //log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Elf_Ehdr -- count of section header table entries: %u\n", hdr->e_shnum);
	//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Elf_Ehdr -- size of whole section header table: %u\n", (hdr->e_shentsize)*(hdr->e_shnum));
    /////////////////

    /////////////////////////////////////////////////////////////////////

	// 1) Memory allocation to store ELF section header table

	/////////////////
	log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 1) Memory allocation to store ELF section header table\n");
    /////////////////

	// Use M_TEMP allocated memory
	sectionheader_table = malloc((hdr->e_shentsize)*(hdr->e_shnum), M_ELFHEADER, flags_mallocELFRead );
	if(sectionheader_table == NULL){
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR IN MALLOC - sectionheader_table\n");
		goto fail;
	}

    // 2) Read ELF section header table

	/////////////////
	log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 2) Lock to serialize the access to the file system\n");
    /////////////////

	// Check if VP is locked

	int prev_locked_status = 0;
	prev_locked_status = VOP_ISLOCKED(imgp->vp);	// 0 -> UNLOCKED, else: previously locked.

	/////////////////
	log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 2.1) Is imgp->vp locked?: %d\n", prev_locked_status);
    /////////////////

	// If not locked, then lock to serialize the access to the file system

	if(prev_locked_status == 0){ // If 0, then UNLOCKED
		vn_lock(imgp->vp, LK_EXCLUSIVE | LK_RETRY);
		//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 2.1) Lock applied - New lock state: %d\n", VOP_ISLOCKED(imgp->vp));
	}


	// Read ELF file to sectionheader_table
	
	/////////////////
	log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 2.2) Read ELF file to sectionheader_table\n");
    /////////////////

	error = vn_rdwr(UIO_READ, imgp->vp, sectionheader_table, (hdr->e_shentsize)*(hdr->e_shnum), hdr->e_shoff,
		UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);
	if (error) {
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR vn_rdwr section header table %d\n", error);
        goto fail1;
    }


	//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- Index of string section header in table %hu -- hex: 0x%x\n", hdr->e_shstrndx, hdr->e_shstrndx);   
	//log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- size of strndx section in bytes: %zu\n", (size_t) sectionheader_table[hdr->e_shstrndx].sh_size); 

	// 3) Elements needed to iterate over each section of the ELF file.

  	char* buff;

	buff = malloc(sectionheader_table[hdr->e_shstrndx].sh_size, M_BUFFER, flags_mallocELFRead);
  	if(buff == NULL){
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR IN MALLOC - buff\n");
    	goto fail1;
  	}

	/////////////////
	log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 3) Malloc-ated sectionheader_table\n");
    ///////////////// 	  

    // 4) Read buff

	error = vn_rdwr(UIO_READ, imgp->vp, buff, sectionheader_table[hdr->e_shstrndx].sh_size, sectionheader_table[hdr->e_shstrndx].sh_offset,
		UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);
	if (error) {
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR vn_rdwr buff %d\n", error);
		goto fail2;
	}

	/////////////////
	log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 4) Buffer read OK\n");
    ///////////////// 

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

	/////////////////
	log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 6) Iterated over sections\n");
    ///////////////// 

    // 8) Check if the desired section (.metadata) was found in earlier iteration

	void* sectiondata;

	if (mm < hdr->e_shnum) {

		// 7) Memory allocation to store data of the section

		sectiondata = malloc(sectionheader_table[mm].sh_size, M_SECTION, flags_mallocELFRead);
		if(sectiondata == NULL){
			log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR IN MALLOC - sectiondata\n");
			goto fail2;
		}

		/////////////////
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 7) Mallocated for section data\n");
		///////////////// 

		// 9) Init variables to section data
		off_t sectiondata_offset = 0;
		size_t sectiondata_size = 0;

		sectiondata_offset = sectionheader_table[mm].sh_offset;    // Points to the start of the desired section
		sectiondata_size = sectionheader_table[mm].sh_size;      // Size of the desired section

		/////////////////
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 8) Sectiondata offset and size\n");
		///////////////// 

		// 11) Read section data

		error = vn_rdwr(UIO_READ, imgp->vp, sectiondata, sectiondata_size, 
						sectiondata_offset, 
						UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);

		if (error) {
			log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // -- ERROR vn_rdwr sectiondata %d\n", error);
			goto fail3;
		}


		/////////////////
		log(LOG_INFO, "\t\t 1) // getMetadataSectionPayload() // LectorELF // 11) Read section data OK\n");
		///////////////// 

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
	// Unlock if the vnode was locked in this function. 
	if(prev_locked_status == 0){ 	// 0 = UNLOCKED before this function.
		VOP_UNLOCK(imgp->vp, 0);	// Lock applied in this function, then unlock to return to prev lock state
	}
fail:
	*return_flag = -1;
    return NULL;
ret:
	// Unlock if the vnode was locked in this function. 
	if(prev_locked_status == 0){ 	// 0 = UNLOCKED before this function.
		VOP_UNLOCK(imgp->vp, 0);	// Lock applied in this function, then unlock to return to prev lock state
	}

	// Free allocated memory 
	free(buff, M_BUFFER);
	free(sectionheader_table, M_ELFHEADER);
	
    return sectiondata;

}



void copyMetadataToProc(void *metadata_addr, int returned_flag, size_t payload_size, struct thread *td){

	/////////////
		log(LOG_INFO, "\t\t 2) ** copyMetadataToProc() ** has been called\n");
	/////////////

	/* * METADATA: proc struct metadata pointer points to returned address */
	td->td_proc->p_metadata_addr = metadata_addr;

	/* * METADATA: Assign metadata returned flag to proc struct */
	td->td_proc->p_metadata_section_flag = returned_flag;

	/* * METADATA: Assign metadata returned size to proc struct */
	td->td_proc->p_metadata_size = payload_size;

	/////////////
		log(LOG_INFO, "\t\t 2) ** copyMetadataToProc() ** EXIT()\n");
	/////////////

}

void decodeMetadataSection(struct thread *td){

	/////////////
		log(LOG_INFO, "\t\t 4) ** decodeMetadataSection() ** has been called\n");
	/////////////

	/* 1) Get Metadata_Hdr address using:
		- Start addr of Metadata_Hdr  = td->td_proc->p_metadata_addr
		- End addr of Metadata_Hdr  = td->td_proc->p_metadata_addr + sizeof(Metadata_Hdr) 
	*/

	void* metadata_hdr_start_addr = (char *) (td->td_proc->p_metadata_addr);
	void* metadata_hdr_end_addr = (char *) (metadata_hdr_start_addr) + sizeof(Metadata_Hdr);
	
	/////////////
		log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // metadata_hdr_end_addr: %p - metadata_hdr_start_addr: %p \n", metadata_hdr_end_addr, metadata_hdr_start_addr);
	/////////////

	Metadata_Hdr metadata_header_decod;
	memcpy(&metadata_header_decod, metadata_hdr_start_addr, sizeof(Metadata_Hdr));

			////////////
			log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // Metadata_Hdr = metadata_header_decod //// m_number_payloads: %d - ph_size: %lu\n", 
				 metadata_header_decod.m_number_payloads, metadata_header_decod.ph_size);
			////////////

	/* 2) Get Payload_Hdr table address:
		- Start addr of Payload_Hdr table  = td->td_proc->p_metadata_addr + td->td_proc->p_metadata_size - (Metadata_Hdr.m_number_payloads * Metadata_Hdr.ph_size)
		- End addr of Payload_Hdr table = td->td_proc->p_metadata_addr + td->td_proc->p_metadata_size
	*/
	
	size_t payload_headers_table_size = (metadata_header_decod.m_number_payloads) * (metadata_header_decod.ph_size);
	void* payload_hdrs_table_end_addr = (char *) (td->td_proc->p_metadata_addr) + (td->td_proc->p_metadata_size);
	void* payload_hdrs_table_start_addr = (char *) (payload_hdrs_table_end_addr) - payload_headers_table_size;

	/////////////
		log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // payload_hdrs_table_start_addr: %p - payload_headers_table_size: %lu \n", payload_hdrs_table_start_addr, payload_headers_table_size);
	/////////////

	Payload_Hdr payload_header_decod;
	void* payhdr_addr = NULL;

	void* payload_addr = (char *) (metadata_hdr_end_addr);

	for(int k = 0; k < metadata_header_decod.m_number_payloads; k++){
		payhdr_addr = &(((Payload_Hdr *)payload_hdrs_table_start_addr)[k]);
		
			/////////////
				log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // payhdr_addr[%d]: %p\n", k, payhdr_addr);
			/////////////

		memcpy(&payload_header_decod, payhdr_addr, sizeof(Payload_Hdr));

			////////////
			log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // Payload_Hdr = payload_header_decod[%d] //// p_function_number: %d - ph_size: %lu\n", 
				k, payload_header_decod.p_function_number, payload_header_decod.p_size);
			////////////

			/* 3) Get each Payload address:
				- Start addr of first Payload  = Start of metadata section
				- End addr of last Payload  = Start addr of Payload_Hdr
			*/		

			/////////////
				log(LOG_INFO, "\t\t 4) // decodeMetadataSection() // LectorELF // payload_addr: %p\n", payload_addr);
			/////////////

		
		switch(payload_header_decod.p_function_number){
			case 1:
			{
				Payload_A payloadA_decod;
				((payload_A_func_wrapper)(payload_functions[payload_header_decod.p_function_number]))(payload_addr, &payloadA_decod);
				break;
			}
			case 2:
			{
				Payload_B payloadB_decod;
				((payload_B_func_wrapper)(payload_functions[payload_header_decod.p_function_number]))(payload_addr, &payloadB_decod);
				break;
			}
			case  3:
			{
				Payload_Binary payloadBinary_decod;
				((payload_Binary_func_wrapper)(payload_functions[payload_header_decod.p_function_number]))(payload_addr, &payloadBinary_decod);
				break;				
			}
			default:
				break;
		}
		
		payload_addr = (char *) (payload_addr) + payload_header_decod.p_size;

	}


	/////////////
		log(LOG_INFO, "\t\t 4) ** decodeMetadataSection() ** EXIT\n");
	/////////////

}
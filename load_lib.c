#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include <fcntl.h>
#include<sys/mman.h>
#include<errno.h>

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;

#define EI_NIDENT 16

typedef struct
{
  FILE* file_d;          /*File descriptor of open library*/
  Elf64_Addr entry;      /*Entry point indicated by ELF header*/
  Elf64_Half phnum;      /*Number of program headers*/
  Elf64_Addr dyn_vaddr;  /*p_vaddr value of dynamic program header*/
  int dyn_num_ents;      /*Number of Dynamic table entries*/
  int dyn_num;           /*Program header number of dynamic program header*/
  Elf64_Addr pht_vaddr;  /*Virtual address of the program header table*/
  Elf64_Word stack_state;  /*Permissions of the stack*/
  Elf64_Addr start_of_mapping;
  Elf64_Addr end_of_mapping;
  Elf64_Addr base_addr;
  Elf64_Addr string_table;
  Elf64_Addr symbol_table;
  int num_sym_entry;
} link_info;

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf_header;

typedef struct
{
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;		/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf_Section_header;

typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  uint16_t	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf_Symtab_ent;

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Program_header;

typedef struct
{
  Elf64_Sxword d_tag;
  union
  {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;

typedef struct
{
  Elf64_Addr mapstart, mapend, dataend, allocend;
  Elf64_Off mapoff;
  int prot;
} command;

long align_down(long addr, long size)
{
  long ans=addr-(addr%size);
  return ans;
}

long align_up(long addr,long size)
{
  if(addr%size==0)
  {
    return addr;
  }
  else
  {
    long ans=align_down(addr,size)+size;
    return ans;
  }
}

link_info* map_library(char* lib_name)
{
  Elf_header* header=(Elf_header*)calloc(1,sizeof(Elf_header));
  link_info* info=(link_info*)calloc(1,sizeof(link_info));
  long pagesize = sysconf(_SC_PAGESIZE);
  FILE* fd=fopen(lib_name,"r");

  info->file_d=fd;
  int data_read=fread(header,sizeof(Elf_header),1,fd);
  if(header->e_type != 3)
  {
    printf("The given file is not a shared object\n");
    return NULL;
  }
  info->entry=header->e_entry;
  info->phnum=header->e_phnum;
  Elf64_Program_header prog_heads[header->e_phnum];
  fseek(fd,header->e_phoff,SEEK_SET);
  data_read=fread(prog_heads,sizeof(Elf64_Program_header),header->e_phnum,fd);

  command commands[info->phnum];
  int num_commands=0;
  int gap=0;
  for(int i=0;i<header->e_phnum;i++)
  {
    if(prog_heads[i].p_type==2)  /*Header type PT_DYNAMIC*/
    {
      info->dyn_vaddr=prog_heads[i].p_vaddr;
      info->dyn_num_ents=prog_heads[i].p_memsz/sizeof(Elf64_Dyn);
      info->dyn_num=i+1;
    }
    if(prog_heads[i].p_type==6)  /*Header Type PT_Phdr*/
    {
      info->pht_vaddr=prog_heads[i].p_vaddr;
    }
    if(prog_heads[i].p_type==1)  /*Header Type PT_Load*/
    {
      commands[num_commands].mapstart = align_down(prog_heads[i].p_vaddr,pagesize);
  	  commands[num_commands].mapend = align_up(prog_heads[i].p_vaddr + prog_heads[i].p_filesz,pagesize);
  	  commands[num_commands].dataend = prog_heads[i].p_vaddr + prog_heads[i].p_filesz;
  	  commands[num_commands].allocend = prog_heads[i].p_vaddr + prog_heads[i].p_memsz;
  	  commands[num_commands].mapoff = align_down(prog_heads[i].p_offset,pagesize);
      if((num_commands>1) && (commands[num_commands].mapstart != commands[num_commands-1].mapend))
      {
        gap=1;
      }
      commands[num_commands].prot=0;
      if(prog_heads[i].p_flags & 4)/*Give read permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_READ;
      }
      if(prog_heads[i].p_flags & 2)/*Give write permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_WRITE;
      }
      if(prog_heads[i].p_flags & 1)/*Give execute permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_EXEC;
      }
      num_commands=num_commands+1;
    }
    if(prog_heads[i].p_type==0x6474e551) /*Header Type PT_GNU_STACK*/
    {
      info->stack_state=prog_heads[i].p_flags;
    }
   /*PT_NOTE and PT_TLS left out*/
  }

  /*Start mapping of library*/
  int fd_new=open(lib_name, O_RDONLY | O_NOCTTY); //using fopen gave errors
  long length_of_mapping=commands[num_commands-1].allocend-commands[0].mapstart;
  info->start_of_mapping=(Elf64_Addr)mmap(NULL,length_of_mapping,commands[0].prot,MAP_PRIVATE|MAP_FILE,fd_new,commands[0].mapoff);
  info->end_of_mapping=info->start_of_mapping+length_of_mapping;
  info->base_addr=info->start_of_mapping-commands[0].mapstart;
  int err_val=mprotect((void *)(commands[0].mapend+info->base_addr),commands[num_commands-1].allocend-commands[0].mapend,PROT_NONE);
  if(commands[0].allocend>commands[0].dataend)
  {
    memset((void *)(commands[0].dataend+info->base_addr),'\0',(commands[0].allocend-commands[0].dataend));
  }
  for(int i=1;i<num_commands;i++)
  {
    length_of_mapping=commands[i].mapend-commands[i].mapstart;
    void *temp_point=mmap((void *)(info->base_addr+commands[i].mapstart),length_of_mapping,commands[i].prot,MAP_PRIVATE|MAP_FILE|MAP_FIXED,fd_new,commands[i].mapoff);
    if(commands[i].allocend>commands[i].dataend)
    {
      memset((void *)(commands[i].dataend+info->base_addr),'\0',(commands[i].allocend-commands[i].dataend));
    }
  }
  if(info->dyn_vaddr != NULL)
  {
    info->dyn_vaddr = info->dyn_vaddr + info->base_addr;
  }
  if(info->pht_vaddr != NULL)
  {
    info->pht_vaddr = info->pht_vaddr + info->base_addr;
  }
  Elf_Section_header section[header->e_shnum];
  fseek(fd,header->e_shoff,SEEK_SET);
  data_read=fread(section,sizeof(Elf_Section_header),header->e_shnum,fd);
  for(int i=0;i < header->e_shnum ;i++)
  {
    if(section[i].sh_type==2)   /*Symbol Table entry*/
    {
      info->symbol_table = section[i].sh_offset;
      info->num_sym_entry = section[i].sh_size/section[i].sh_entsize;
    }
    if(section[i].sh_type==3)   /*String Table entry*/
    {
      info->string_table = section[i].sh_offset;
    }
  }
  return info;
}
void * get_function(link_info* info,char *func_name)
{
  Elf_Symtab_ent symbols[info->num_sym_entry];
  fseek(info->file_d,info->symbol_table,SEEK_SET);
  int data_red=fread(symbols,sizeof(Elf_Symtab_ent),info->num_sym_entry,info->file_d);

  char str[strlen(func_name)+1];
  for(int i=0;i < info->num_sym_entry;i++)
  {
    fseek(info->file_d,info->string_table+symbols[i].st_name,SEEK_SET);
    fread(str,strlen(func_name)+1,1,info->file_d);
    if(strncmp(str,func_name,strlen(func_name)+1)==0)
    {
      void *addr=(void *)(info->base_addr+symbols[i].st_value);
      return addr;
    }
  }
}
int main()
{
  link_info* handle=map_library("./lib_test.so");
  int (*fibo)(int);
  fibo = (int (*)(int))get_function(handle, "fibonacci");
  printf("%d\n",(*fibo)(10));
  return 0;
}

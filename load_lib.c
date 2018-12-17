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

#define PT_DYNAMIC 2
#define PT_PHDR 6
#define PT_LOAD 1
#define PT_GNU_STACK 0x6474e551

#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_DYNAMIC 6

#define DT_PLTRELSZ 2
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_JMPREL 23

#define R_X86_64_GLOB_DAT 6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE 8

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

typedef struct
{
        Elf64_Addr      r_offset;
        Elf64_Xword     r_info;
        Elf64_Sxword    r_addend;
} Elf64_Rela;

#define ELF64_R_SYM(info)             ((info)>>32)
#define ELF64_R_TYPE(info)            ((Elf64_Word)(info))
#define ELF64_R_INFO(sym, type)       (((Elf64_Xword)(sym)<<32)+(Elf64_Xword)(type))

/* Truncates the passed number to the nearest multiple of size*/
long align_down(long addr, long size)
{
  long ans=addr-(addr%size);
  return ans;
}

/*Round up the given number to the next multiple of size*/
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

/*Maps library into memory and returns a handle to the mapped region*/
link_info* map_library(char* lib_name)
{
  Elf_header* header=(Elf_header*)calloc(1,sizeof(Elf_header));
  link_info* info=(link_info*)calloc(1,sizeof(link_info));
  long pagesize = sysconf(_SC_PAGESIZE);
  FILE* fd=fopen(lib_name,"r");
  if(fd==NULL)
  {
    printf("Cannot open the shared library file!\n");
    return NULL;
  }

  info->file_d=fd;
  int data_read=fread(header,sizeof(Elf_header),1,fd);
  if(data_read != 1)
  {
    printf("Error reading Elf Header!\n");
  }
  if(header->e_type != 3)
  {
    printf("The given file is not a shared object\n");
    return NULL;
  }
  info->entry=header->e_entry;
  info->phnum=header->e_phnum;
  Elf64_Program_header prog_heads[header->e_phnum];
  if(fseek(fd,header->e_phoff,SEEK_SET) == -1)
  {
    printf("Error parsing file\n");
  }
  data_read=fread(prog_heads,sizeof(Elf64_Program_header),header->e_phnum,fd);
  if(data_read != header->e_phnum)
  {
    printf("Error reading program Header table\n");
  }

  command commands[info->phnum];
  int num_commands=0;
  for(int i=0;i<header->e_phnum;i++)
  {
    if(prog_heads[i].p_type==PT_DYNAMIC)  /*Header type PT_DYNAMIC*/
    {
      info->dyn_vaddr=prog_heads[i].p_vaddr;
      info->dyn_num_ents=prog_heads[i].p_memsz/sizeof(Elf64_Dyn);
      info->dyn_num=i+1;
    }
    if(prog_heads[i].p_type==PT_PHDR)  /*Header Type PT_Phdr*/
    {
      info->pht_vaddr=prog_heads[i].p_vaddr;
    }
    if(prog_heads[i].p_type==PT_LOAD)  /*Header Type PT_Load*/
    {
      commands[num_commands].mapstart = align_down(prog_heads[i].p_vaddr,pagesize);
  	  commands[num_commands].mapend = align_up(prog_heads[i].p_vaddr + prog_heads[i].p_filesz,pagesize);
  	  commands[num_commands].dataend = prog_heads[i].p_vaddr + prog_heads[i].p_filesz;
  	  commands[num_commands].allocend = prog_heads[i].p_vaddr + prog_heads[i].p_memsz;
  	  commands[num_commands].mapoff = align_down(prog_heads[i].p_offset,pagesize);
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
    if(prog_heads[i].p_type==PT_GNU_STACK) /*Header Type PT_GNU_STACK*/
    {
      info->stack_state=prog_heads[i].p_flags;
    }
   /*PT_NOTE and PT_TLS left out*/
  }
  /*Start mapping of library*/
  int fd_new=open(lib_name, O_RDONLY | O_NOCTTY); //using fopen gave errors
  if(fd_new == -1)
  {
    printf("Error opening file\n");
  }
  long length_of_mapping=commands[num_commands-1].allocend-commands[0].mapstart;
  info->start_of_mapping=(Elf64_Addr)mmap(NULL,length_of_mapping,commands[0].prot,MAP_PRIVATE|MAP_FILE,fd_new,commands[0].mapoff);
  if(info->start_of_mapping == -1)
  {
    printf("Mmap failed\n");
  }
  info->end_of_mapping=info->start_of_mapping+length_of_mapping;
  info->base_addr=info->start_of_mapping-commands[0].mapstart;
  int err_val=mprotect((void *)(commands[0].mapend+info->base_addr),commands[num_commands-1].allocend-commands[0].mapend,PROT_NONE);
  if(err_val == -1)
  {
    printf("Setting memory protections failed\n");
  }
  if(commands[0].allocend>commands[0].dataend)
  {
    memset((void *)(commands[0].dataend+info->base_addr),'\0',(commands[0].allocend-commands[0].dataend));
  }
  for(int i=1;i<num_commands;i++)
  {
    length_of_mapping=commands[i].mapend-commands[i].mapstart;
    void *temp_point=mmap((void *)(info->base_addr+commands[i].mapstart),length_of_mapping,commands[i].prot,MAP_PRIVATE|MAP_FILE|MAP_FIXED,fd_new,commands[i].mapoff);
    if(temp_point == -1)
    {
      printf("Mmap failed\n");
    }
    if(commands[i].allocend>commands[i].dataend)
    {
      memset((void *)(commands[i].dataend+info->base_addr),'\0',(commands[i].allocend-commands[i].dataend));
    }
  }
  if(close(fd_new) == -1)
  {
    printf("Error closing file\n");
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
  if(fseek(fd,header->e_shoff,SEEK_SET) == -1)
  {
    printf("Error parsing file\n");
  }
  data_read=fread(section,sizeof(Elf_Section_header),header->e_shnum,fd);
  if(data_read != header->e_shnum)
  {
    printf("Error reading section header\n");
  }
  Elf64_Addr dynamic;
  int num_dyn_ent;
  for(int i=0;i < header->e_shnum ;i++)
  {
    if(section[i].sh_type==SHT_SYMTAB)   /*Symbol Table entry*/
    {
      info->symbol_table = section[i].sh_offset;
      info->num_sym_entry = section[i].sh_size/section[i].sh_entsize;
    }
    if(section[i].sh_type==SHT_STRTAB)   /*String Table entry*/
    {
      info->string_table = section[i].sh_offset;
    }
    if(section[i].sh_type==SHT_DYNAMIC)  /* DYNAMIC Section */
    {
      dynamic=section[i].sh_offset;
      num_dyn_ent=section[i].sh_size/section[i].sh_entsize;
    }
  }
  Elf64_Dyn dyn_entries[num_dyn_ent];
  Elf64_Addr relocation_addr;
  int num_relocations;
  if(fseek(fd,dynamic,SEEK_SET) == -1)
  {
    printf("Error paring file\n");
  }
  data_read=fread(dyn_entries,sizeof(Elf64_Dyn),num_dyn_ent,fd);
  if(data_read != num_dyn_ent)
  {
    printf("Error reading file\n");
  }
  void (*init)();

  Elf64_Addr dyn_sym_offset;
  int sym_tabsize;
  int dyn_sym_num;
  int plt_ents;
  Elf64_Addr plt_offset;
  for(int i=0;i<num_dyn_ent;i++)
  {
    if(dyn_entries[i].d_tag==DT_SYMTAB) /*Symbol Table*/
    {
      dyn_sym_offset=dyn_entries[i].d_un.d_ptr;
    }
    if(dyn_entries[i].d_tag==DT_SYMENT) /*Size of symbol table*/
    {
      sym_tabsize=dyn_entries[i].d_un.d_val;
    }
    if(dyn_entries[i].d_tag==DT_RELA) /* DT_RELA*/
    {
      relocation_addr=dyn_entries[i].d_un.d_ptr;
    }
    if(dyn_entries[i].d_tag==DT_RELASZ) /*DT_RELASZ*/
    {
      num_relocations=dyn_entries[i].d_un.d_val/sizeof(Elf64_Rela);
    }
    if(dyn_entries[i].d_tag==DT_INIT)  /*DT_INIT*/
    {
      init = info->base_addr+dyn_entries[i].d_un.d_ptr;
    }
    if(dyn_entries[i].d_tag==DT_PLTRELSZ)  /*Size of relocation entries associated with PLT*/
    {
      plt_ents=dyn_entries[i].d_un.d_val;
    }
    if(dyn_entries[i].d_tag==DT_JMPREL) /*DT_JMPREL*/
    {
      plt_offset=dyn_entries[i].d_un.d_ptr;
    }
  }
  plt_ents=plt_ents/sizeof(Elf64_Rela);

  dyn_sym_num=sym_tabsize/sizeof(Elf_Symtab_ent);
  Elf_Symtab_ent symbols[dyn_sym_num];
  if(fseek(info->file_d,dyn_sym_offset,SEEK_SET) == -1)
  {
    printf("Error parsing file\n");
  }
  data_read=fread(symbols,sizeof(Elf_Symtab_ent),info->num_sym_entry,info->file_d);
  if(data_read != info->num_sym_entry)
  {
    printf("Error reading file\n");
  }

  Elf64_Rela relocations[num_relocations];
  if(fseek(fd,relocation_addr,SEEK_SET) == -1)
  {
    printf("Error parsing file\n");
  }
  data_read=fread(relocations,sizeof(Elf64_Rela),num_relocations,fd);
  if(data_read != num_relocations)
  {
    printf("Error reading file\n");
  }
  for(int i=0;i<num_relocations;i++)
  {
    int sym_index=ELF64_R_SYM(relocations[i].r_info);
    int type=ELF64_R_TYPE(relocations[i].r_info);
    Elf64_Addr* reloc_addr=info->base_addr+relocations[i].r_offset;
    if(type==6)
    {
      *(reloc_addr)=symbols[sym_index].st_value;
    }
    if(type==8)
    {
      *(reloc_addr)=info->base_addr+relocations[i].r_addend;
    }
  }
  Elf64_Rela plt_relocations[plt_ents];
  if(fseek(fd,plt_offset,SEEK_SET) == -1)
  {
    printf("Error parsing file\n");
  }
  data_read=fread(plt_relocations,sizeof(Elf64_Rela),plt_ents,fd);
  if(data_read != plt_ents)
  {
    printf("Error reading file\n");
  }
  for(int i=0;i<plt_ents;i++)
  {
    int sym_index=ELF64_R_SYM(plt_relocations[i].r_info);
    int type=ELF64_R_TYPE(plt_relocations[i].r_info);
    Elf64_Addr* reloc_addr=info->base_addr+plt_relocations[i].r_offset;
    if(type==7)
    {
      *(reloc_addr)=symbols[sym_index].st_value;
    }
  }
  (*init)();

  for(int i=0;i<num_relocations;i++)
  {
    int sym_index=ELF64_R_SYM(relocations[i].r_info);
    int type=ELF64_R_TYPE(relocations[i].r_info);
    Elf64_Addr* reloc_addr=info->base_addr+relocations[i].r_offset;
    if(type==R_X86_64_GLOB_DAT)
    {
      *(reloc_addr)=info->base_addr+symbols[sym_index].st_value;
    }
    if(type==R_X86_64_RELATIVE)
    {
      *(reloc_addr)=info->base_addr+relocations[i].r_addend;
    }
  }
  for(int i=0;i<plt_ents;i++)
  {
    int sym_index=ELF64_R_SYM(plt_relocations[i].r_info);
    int type=ELF64_R_TYPE(plt_relocations[i].r_info);
    Elf64_Addr* reloc_addr=info->base_addr+plt_relocations[i].r_offset;
    if(type==R_X86_64_JUMP_SLOT)
    {
      *(reloc_addr)=info->base_addr+symbols[sym_index].st_value;
    }
  }
  return info;
}
void * get_function(link_info* info,char *func_name)
{
  Elf_Symtab_ent symbols[info->num_sym_entry];
  if(fseek(info->file_d,info->symbol_table,SEEK_SET) == -1)
  {
    printf("Error parsing library\n");
  }
  int data_read=fread(symbols,sizeof(Elf_Symtab_ent),info->num_sym_entry,info->file_d);
  if(data_read != info->num_sym_entry)
  {
    printf("Error parsing library\n");
  }
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
  return NULL;
}
int main(int argc, char* argv[])
{
  link_info* handle=map_library("./lib_test.so");
  if(handle == NULL)
  {
    printf("Error opening library\n");
    return 1;
  }
  int (*fibo)(int);
  fibo = (int (*)(int))get_function(handle, "fibonacci");
  if(fibo == NULL)
  {
    printf("Function not found");
  }
  else
  {
    printf("%d\n",(*fibo)(atoi(argv[1])));
  }
  return 0;
}

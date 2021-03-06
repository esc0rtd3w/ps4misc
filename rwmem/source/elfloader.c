#include <stdlib.h>
#include <string.h>

#include <elfloader.h>

#define elfRelocationSymbol __ELFN(R_SYM)
#define elfRelocationType __ELFN(R_TYPE)
#define elfRelocationInfo __ELFN(R_INFO)

#define elfSymbolBind __ELFN(ST_BIND)
#define elfSymbolType __ELFN(ST_TYPE)
#define elfSymbolInfo __ELFN(ST_INFO)

#define elfIsElf(e) IS_ELF(*elfHeader(e)) // FIXME: Null deref

#define elfClass(e) (e == NULL ? 0 : e->data[4])
#define elfEncoding(e) (e == NULL ? 0 : e->data[5])
#define elfVersion(e) (e == NULL ? 0 : e->data[6])
#define elfABI(e) (e == NULL ? 0 : e->data[7])

/* Constants */

enum{ ELF_MAXIMAL_STRING_LENGTH = 4096 };

/* Type */

typedef struct Elf // FIXME: We could cache a lot of offsets here to inc. performance
{
    uint8_t *data;
    size_t size; // FIXME: Do more checks on size
}
Elf;

size_t elfGetSize(Elf *elf)
{
    return elf->size;
}

uint8_t *elfGetData(Elf *elf)
{
    return elf->data;
}

/* --- elf header --- */

ElfHeader *elfHeader(Elf *elf)
{
    if(!elf)
        return NULL;
    return (ElfHeader *)elf->data;
}

uint64_t elfEntry(Elf *elf)
{
    if(!elf)
        return 0;
    ElfHeader *h = elfHeader(elf);
    if(!h)
        return 0;
    return h->e_entry;
}

uint64_t elfLargestAlignment(Elf *elf) //ignore ...
{
    uint16_t index = 0;
    uint64_t alignment = 0;

    while(1)
    {
        ElfSegment *h = elfSegment(elf, &index, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_LOAD);
        if(!h)
            break;

        // FIXME: Tired of bogus 2MB alignment -> ignore
        if(alignment < h->p_align && h->p_align < 0x200000)
            alignment = h->p_align;
        ++index;
    }
    return alignment;
}

size_t elfMemorySize(Elf *elf)
{
    ElfSection *sections;
    ElfSegment *segments;

    uint16_t size;
    uint16_t length;
    uint16_t index;

    size_t memorySize = 0;

    if(!elf)
        return 0;

    segments = elfSegments(elf, &size, &length);
    if(segments)
    {
        for(index = 0; index < length; ++index)
        {
            ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
            if(memorySize < s->p_paddr + s->p_memsz)
                memorySize = s->p_paddr + s->p_memsz;
        }
    }
    else
    {
        length = 0;
        sections = elfSections(elf, &size, &length);
        if(!sections)
            return 0;
        for(index = 0; index < length; ++index)
        {
            ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
            if(memorySize < s->sh_addr + s->sh_size)
                memorySize = s->sh_addr + s->sh_size;
        }
    }

    return memorySize;
}

/* --- elf section header --- */

char *elfSectionStrings(Elf *elf, uint64_t *size)
{
    ElfHeader *h;
    uint16_t i;
    ElfSection *s;
    h = elfHeader(elf);
    i = h->e_shstrndx;
    s = elfSection(elf, &i, ELF_SECTION_ATTRIBUTE_NONE, 0);
    if(size)
        *size = s->sh_size;
    return (char *)elf->data + s->sh_offset;
}

uint64_t elfSectionAttribute(ElfSection *elfSection, ElfSectionAttribute attribute)
{
    switch(attribute)
    {
        case ELF_SECTION_ATTRIBUTE_NAME:
            return elfSection->sh_name;
        case ELF_SECTION_ATTRIBUTE_TYPE:
            return elfSection->sh_type;
        case ELF_SECTION_ATTRIBUTE_FLAGS:
            return elfSection->sh_flags;
        case ELF_SECTION_ATTRIBUTE_ADDRESS:
            return elfSection->sh_addr;
        case ELF_SECTION_ATTRIBUTE_OFFSET:
            return elfSection->sh_offset;
        case ELF_SECTION_ATTRIBUTE_SIZE:
            return elfSection->sh_size;
        case ELF_SECTION_ATTRIBUTE_LINK:
            return elfSection->sh_link;
        case ELF_SECTION_ATTRIBUTE_INFO:
            return elfSection->sh_info;
        case ELF_SECTION_ATTRIBUTE_MEMORY_ALIGNMENT:
            return elfSection->sh_addralign;
        case ELF_SECTION_ATTRIBUTE_ENTRY_SIZE:
            return elfSection->sh_entsize;
        default:
            break;
    }
    return 0;
}

ElfSection *elfSections(Elf *elf, uint16_t *size, uint16_t *length)
{
    ElfHeader *h;

    if(!elf)
        return NULL;

    h = elfHeader(elf);

    if(h->e_shoff == 0)
        return NULL;

    if(size != NULL)
        *size = h->e_shentsize;
    if(length != NULL)
        *length = h->e_shnum;

    return (ElfSection *)(elf->data + h->e_shoff);
}

ElfSection *elfSection(Elf *elf, uint16_t *index, ElfSectionAttribute attribute, uint64_t value)
{
    uint16_t size;
    uint16_t length;
    ElfSection *h, *t;
    uint16_t i = 0;

    if(!index)
        index = &i;

    h = elfSections(elf, &size, &length);

    if(!h)
        return NULL;

    for(; *index < length; ++(*index))
    {
        t = (ElfSection *)((uint8_t *)h + *index * size);
        if(attribute == ELF_SECTION_ATTRIBUTE_NONE || elfSectionAttribute(t, attribute) == value)
            return t;
    }

    return NULL;
}

ElfSection *elfSectionByName(Elf *elf, char *name)
{
    uint64_t size;
    char *mem = elfSectionStrings(elf, &size);

    uint32_t offset = elfStringToOffset(mem, size, name);
    ElfSection *sh = elfSection(elf, NULL, ELF_SECTION_ATTRIBUTE_NAME, offset);

    return sh;
}

/* --- elf segment header --- */

uint64_t elfSegmentAttribute(ElfSegment *elfSegment, ElfSegmentAttribute attribute)
{
    switch(attribute)
    {
        case ELF_SEGMENT_ATTRIBUTE_TYPE:
            return elfSegment->p_type;
        case ELF_SEGMENT_ATTRIBUTE_FLAGS:
            return elfSegment->p_flags;
        case ELF_SEGMENT_ATTRIBUTE_OFFSET:
            return elfSegment->p_offset;
        case ELF_SEGMENT_ATTRIBUTE_VIRTUAL_ADDRESS:
            return elfSegment->p_vaddr;
        case ELF_SEGMENT_ATTRIBUTE_PHYSICAL_ADDRESS:
            return elfSegment->p_paddr;
        case ELF_SEGMENT_ATTRIBUTE_FILE_SIZE:
            return elfSegment->p_filesz;
        case ELF_SEGMENT_ATTRIBUTE_MEMORY_SIZE:
            return elfSegment->p_memsz;
        case ELF_SEGMENT_ATTRIBUTE_ALIGNMENT:
            return elfSegment->p_align;
        default:
            break;
    }
    return 0;
}

ElfSegment *elfSegments(Elf *elf, uint16_t *size, uint16_t *length)
{
    ElfHeader *h;

    if(!elf)
        return NULL;

    h = elfHeader(elf);

    if(h->e_phoff == 0)
        return NULL;

    if(size != NULL)
        *size = h->e_phentsize;
    if(length != NULL)
        *length = h->e_phnum;

    return (ElfSegment *)(elf->data + h->e_phoff);
}

ElfSegment *elfSegment(Elf *elf, uint16_t *index, ElfSegmentAttribute attribute, uint64_t value)
{
    uint16_t size;
    uint16_t length;
    ElfSegment *h, *t;
    uint16_t i = 0;

    if(!index)
        index = &i;

    h = elfSegments(elf, &size, &length);

    if(!h)
        return NULL;

    for(; *index < length; ++(*index))
    {
        t = (ElfSegment *)((uint8_t *)h + *index * size);
        if(attribute == ELF_SEGMENT_ATTRIBUTE_NONE || elfSegmentAttribute(t, attribute) == value)
            return t;
    }

    return NULL;
}

/* --- elf dynamic section --- */

uint64_t elfDynamicAttribute(ElfDynamic *elfDynamic, ElfDynamicAttribute attribute)
{
    switch(attribute)
    {
        case ELF_DYNAMIC_ATTRIBUTE_TAG:
            return elfDynamic->d_tag;
        case ELF_DYNAMIC_ATTRIBUTE_VALUE:
            return elfDynamic->d_un.d_val;
        case ELF_DYNAMIC_ATTRIBUTE_POINTER:
            return elfDynamic->d_un.d_ptr;
        default:
            break;
    }
    return 0;
}

uint16_t elfDynamicsLength(ElfDynamic *dyn)
{
    uint16_t i = 0;
    if(dyn != NULL)
        for(;dyn->d_tag != DT_NULL; ++dyn)
            ++i;
    return i;
}

ElfDynamic *elfDynamics(Elf *elf, uint16_t *size, uint16_t *length)
{
    ElfSection *h;
    ElfSegment *h2;

    if(!elf)
        return NULL;

    if((h = elfSection(elf, NULL, ELF_SECTION_ATTRIBUTE_TYPE, SHT_DYNAMIC)))
    {
        if(size != NULL)
            *size = h->sh_entsize;
        if(length != NULL)
            *length = h->sh_size / h->sh_entsize;

        return (ElfDynamic *)(elf->data + h->sh_offset);
    }
    else if((h2 = elfSegment(elf, NULL, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_DYNAMIC)))
    {
        if(size != NULL)
            *size = sizeof(ElfDynamic);
        if(length != NULL) //h2->p_filesz / sizeof(ElfDynamic);
            *length = elfDynamicsLength((ElfDynamic *)(elf->data + h2->p_offset));

        return (ElfDynamic *)(elf->data + h2->p_offset);
    }

    return NULL;
}

ElfDynamic *elfDynamic(Elf *elf, uint16_t *index, ElfDynamicAttribute attribute, uint64_t value)
{
    uint16_t size;
    uint16_t length;
    ElfDynamic *h, *t;
    uint16_t i = 0;

    if(!index)
        index = &i;

    h = elfDynamics(elf, &size, &length);

    if(!h)
        return NULL;

    for(; *index < length; ++(*index))
    {
        t = (ElfDynamic *)((uint8_t *)h + *index * size);
        if(attribute == ELF_DYNAMIC_ATTRIBUTE_NONE || elfDynamicAttribute(t, attribute) == value)
            return t;
    }

    return NULL;
}

ElfDynamic *elfLoadedDynamics(Elf *elf, uint16_t *size, uint16_t *length)
{
    //ElfSection *h;
    ElfSegment *h2;

    if(!elf)
        return NULL;

    if((h2 = elfSegment(elf, NULL, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_DYNAMIC)))
    {
        if(size != NULL)
            *size = sizeof(ElfDynamic);
        if(length != NULL)
            *length = elfDynamicsLength((ElfDynamic *)h2->p_vaddr);

        return (ElfDynamic *)h2->p_vaddr;
    }

    return NULL;
}

ElfDynamic *elfLoadedDynamic(Elf *elf, uint16_t *index, ElfDynamicAttribute attribute, uint64_t value)
{
    uint16_t size;
    uint16_t length;
    ElfDynamic *h, *t;
    uint16_t i = 0;

    if(!index)
        index = &i;

    h = elfLoadedDynamics(elf, &size, &length);

    if(!h)
        return NULL;

    for(; *index < length; ++(*index))
    {
        t = (ElfDynamic *)((uint8_t *)h + *index * size);
        if(attribute == ELF_DYNAMIC_ATTRIBUTE_NONE || elfDynamicAttribute(t, attribute) == value)
            return t;
    }

    return NULL;
}

/* --- elf string tables --- */

char *elfStringFromIndex(char *mem, uint64_t size, uint32_t index)
{
    uint64_t i, j = 0;

    if(!mem)
        return NULL;

    if(index == 0)
        return mem;

    for(i = 0; i < size - 1; ++i)
        if(mem[i] == '\0' && ++j == index)
            return mem + i + 1;

    return NULL;
}

char *elfStringFromOffset(char *mem, uint64_t size, uint32_t offset)
{
    if(!mem || offset >= size)
        return NULL;

    return mem + offset;
}

uint32_t elfStringToOffset(char *mem, uint64_t size, char *str)
{
    uint64_t i, j;

    if(!str)
        return 0;

    for(i = 0; i < size; ++i)
    {
        for(j = 0; j < ELF_MAXIMAL_STRING_LENGTH && mem[i + j] == str[j]; ++j)
            if(str[j] == '\0')
                return i;
    }

    return 0;
}

uint32_t elfStringToIndex(char *mem, uint64_t size, char *str)
{
    uint64_t index, i, j;

    if(!str)
        return 0;

    index = 0;
    for(i = 0; i < size; ++i)
    {
        for(j = 0; j < ELF_MAXIMAL_STRING_LENGTH && mem[i + j] == str[j]; ++j)
            if(str[j] == '\0')
                return index;

        if(mem[i] == '\0')
            index++;
    }

    return 0;
}

/* --- elf relocations --- */

uint64_t elfAddendRelocationAttribute(ElfAddendRelocation *elfAddendRelocation, ElfAddendRelocationAttribute attribute)
{
    switch(attribute)
    {
        case ELF_ADDEND_RELOCATION_ATTRIBUTE_INFO:
            return elfAddendRelocation->r_info;
        case ELF_ADDEND_RELOCATION_ATTRIBUTE_OFFSET:
            return elfAddendRelocation->r_offset;
        case ELF_ADDEND_RELOCATION_ATTRIBUTE_ADDEND:
            return elfAddendRelocation->r_addend;
        default:
            break;
    }
    return 0;
}

ElfAddendRelocation *elfAddendRelocations(Elf *elf, char *name, uint16_t *size, uint16_t *length)
{
    ElfSection *h;

    h = elfSectionByName(elf, name);

    if(!h || h->sh_type != SHT_RELA)
        return NULL;

    if(size != NULL)
        *size = h->sh_entsize;
    if(length != NULL)
        *length = h->sh_size / h->sh_entsize;

    return (ElfAddendRelocation *)(elf->data + h->sh_offset);
}

// FIXME this is not performant, better to pass in the base ElfAddendRelocation *, size and length
/*
ElfAddendRelocation *elfAddendRelocation(Elf *elf, char *name, uint16_t *index, ElfAddendRelocationAttribute attribute, uint64_t value)
{
    uint16_t size;
    uint16_t length;
    ElfAddendRelocation *h, *t;
    uint16_t i = 0;

    if(!index)
        index = &i;

    h = elfAddendRelocations(elf, name, &size, &length);

    if(!h)
        return NULL;

    for(; *index < length; ++(*index))
    {
        t = (ElfAddendRelocation *)((uint8_t *)h + *index * size);
        if(attribute == ElfAddendRelocationAttributeNone || elfAddendRelocationAttribute(t, attribute) == value)
            return t;
    }

    return NULL;
}
*/

/* --- elf symbols --- */

uint64_t elfSymbolAttribute(ElfSymbol *elfSymbol, ElfSymbolAttribute attribute)
{
    switch(attribute)
    {
        case ELF_SYMBOL_ATTRIBUTE_NAME:
            return elfSymbol->st_name;
        case ELF_SYMBOL_ATTRIBUTE_INFO:
            return elfSymbol->st_info;
        case ELF_SYMBOL_ATTRIBUTE_UNUSED:
            return elfSymbol->st_other;
        case ELF_SYMBOL_ATTRIBUTE_SECTION_INDEX:
            return elfSymbol->st_shndx;
        case ELF_SYMBOL_ATTRIBUTE_VALUE:
            return elfSymbol->st_value;
        case ELF_SYMBOL_ATTRIBUTE_SIZE:
            return elfSymbol->st_size;
        default:
            break;
    }
    return 0;
}

ElfSymbol *elfSymbols(Elf *elf, char *name, uint16_t *size, uint16_t *length)
{
    ElfSection *h;

    h = elfSectionByName(elf, name);

    if(!h || (h->sh_type != SHT_SYMTAB && h->sh_type != SHT_DYNSYM))
        return NULL;

    if(size != NULL)
        *size = h->sh_entsize;
    if(length != NULL)
        *length = h->sh_size / h->sh_entsize;

    return (ElfSymbol *)(elf->data + h->sh_offset);
}

/*
ElfSymbol *elfSymbol(Elf *elf, char *name, uint16_t *index, ElfSymbolAttribute attribute, uint64_t value)
{
    uint16_t size;
    uint16_t length;
    ElfSymbol *h, *t;
    uint16_t i = 0;

    if(!index)
        index = &i;

    h = elfSymbols(elf, name, &size, &length);

    if(!h)
        return NULL;

    for(; *index < length; ++(*index))
    {
        t = (ElfSymbol *)((uint8_t *)h + *index * size);
        if(attribute == ElfSymbolAttributeNone || elfSymbolAttribute(t, attribute) == value)
            return t;
    }

    return NULL;
}*/

/* actions */

Elf *elfCreate(void *data, size_t size)
{
    Elf *elf, t;

    if(data == NULL)
        return NULL;

    t.data = data;
    t.size = size;

    if(!elfIsElf(&t))
        return NULL;

    elf = malloc(sizeof(Elf));
    elf->data = (uint8_t *)data;
    elf->size = size;

    return elf;
}

Elf *elfCreateLocal(void *elfl, void *data, size_t size)
{
    Elf *elf, t;

    if(elfl == NULL || data == NULL)
        return NULL;

    t.data = data;
    t.size = size;

    if(!elfIsElf(&t))
        return NULL;

    elf = (Elf *)elfl;
    elf->data = (uint8_t *)data;
    elf->size = size;

    return elf;
}

Elf *elfCreateLocalUnchecked(void *elfl, void *data, size_t size)
{
    Elf *elf;

    if(elfl == NULL || data == NULL)
        return NULL;

    elf = (Elf *)elfl;
    elf->data = (uint8_t *)data;
    elf->size = size;

    return elf;
}

void *elfDestroy(Elf *elf)
{
    void *data;

    if(elf == NULL)
        return NULL;

    data = elf->data;
    free(elf);

    return data;
}

void elfDestroyAndFree(Elf *elf)
{
    void *d;

    if(elf == NULL)
        return;

    d = elfDestroy(elf);
    if(d)
        free(d);
}

int elfLoaderInstantiate(int procpid, Elf *elf, void *memory)
{
    ElfSection *sections;
    ElfSegment *segments;

    uint16_t size;
    uint16_t length;
    uint16_t index;

    if(elf == NULL)
        return ELF_LOADER_RETURN_ELF_NULL;
    if(memory == NULL)
        return ELF_LOADER_RETURN_NO_WRITABLE_MEMORY;

    segments = elfSegments(elf, &size, &length);
    if(segments)
    {
        for(index = 0; index < length; ++index)
        {
            ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
            if(s->p_filesz)
                write_process_form_sys(procpid, (uint64_t)memory + s->p_paddr, elf->data + s->p_offset, s->p_filesz);
            // if(s->p_memsz - s->p_filesz)
            //     memset((char *)memory + s->p_paddr + s->p_filesz, 0, s->p_memsz - s->p_filesz);
        }
    }
    else
    {
        length = 0;
        sections = elfSections(elf, &size, &length);
        if(!sections)
            return 0;
        for(index = 0; index < length; ++index)
        {
            ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
            if(!(s->sh_flags & SHF_ALLOC))
                continue;
            if(s->sh_size)
                write_process_form_sys(procpid, (uint64_t)memory + s->sh_addr, elf->data + s->sh_offset, s->sh_size);
        }
    }

    return ELF_LOADER_RETURN_OK;
}

int elfLoaderRelativeAddressIsExecutable(Elf *elf, int64_t address)
{
    ElfSection *sections;
    ElfSegment *segments;

    uint16_t size;
    uint16_t length;
    uint16_t index;

    if(elf == NULL)
        return 0;

    segments = elfSegments(elf, &size, &length);
    if(segments)
    {
        for(index = 0; index < length; ++index)
        {
            ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
            if(address >= s->p_paddr && address <= s->p_paddr + s->p_memsz)
                return s->p_flags & PF_X;
        }
    }
    else
    {
        length = 0;
        sections = elfSections(elf, &size, &length);
        if(!sections)
            return ELF_LOADER_RETURN_NO_SECTIONS_OR_SEGMENTS;
        for(index = 0; index < length; ++index)
        {
            ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
            if(address >= s->sh_addr && address <= s->sh_addr + s->sh_size)
                return s->sh_flags & SHF_EXECINSTR;
        }
    }

    return 1; // FIXME: Recheck
}

int elfLoaderRelocate(int procpid, Elf *elf, void *executable)
{
    int i, j;

    uint16_t relocationSize = 0;
    uint16_t relocationsLength = 0;
    ElfAddendRelocation *relocations;

    uint16_t dynamicSymbolSize = 0;
    uint16_t dynamicSymbolsLength = 0;
    ElfSymbol *dynamicSymbols;

    char *r1 = ".rela.dyn";
    char *r2 = ".rela.plt";
    char *rel[2] = {r1, r2};

    if(elf == NULL)
        return ELF_LOADER_RETURN_ELF_NULL;
    if(executable == NULL)
        return ELF_LOADER_RETURN_NO_EXECUTABLE_MEMORY;

    dynamicSymbols = elfSymbols(elf, ".dynsym", &dynamicSymbolSize, &dynamicSymbolsLength);
    //symbols = elfSymbols(elf, ".symtab", &symbolSize, &symbolsLength);

    for(j = 0; j < sizeof(rel) / sizeof(rel[0]); ++j)
    {
        relocationsLength = 0;
        relocations = elfAddendRelocations(elf, rel[j], &relocationSize, &relocationsLength);

        for(i = 0; i < relocationsLength; ++i)
        {
            ElfSymbol *symbol;
            ElfAddendRelocation *relocation = (ElfAddendRelocation *)(((uint8_t *)relocations) + relocationSize * i);
            uint16_t relocationType = (uint16_t)elfRelocationType(relocation->r_info);
            uint16_t relocationSymbol = (uint16_t)elfRelocationSymbol(relocation->r_info);
            uint64_t offset = (uint64_t)executable + relocation->r_offset;
            uint64_t value = 0;

            switch(relocationType)
            {
                case R_X86_64_RELATIVE:
                    value = relocation->r_addend + offset;
                    break;
                case R_X86_64_64:
                    return ELF_LOADER_RETURN_UNKNOWN_RELOCATION;
                    symbol = (ElfSymbol *)(((uint8_t *)dynamicSymbols) + dynamicSymbolSize * relocationSymbol);
                    value = symbol->st_value + relocation->r_addend;
                    break;
                case R_X86_64_JMP_SLOT:
                case R_X86_64_GLOB_DAT:
                    return ELF_LOADER_RETURN_UNKNOWN_RELOCATION;
                    symbol = (ElfSymbol *)(((uint8_t *)dynamicSymbols) + dynamicSymbolSize * relocationSymbol);
                    value = symbol->st_value;
                    break;
                default:
                    return ELF_LOADER_RETURN_UNKNOWN_RELOCATION;
            }

            // if(elfLoaderRelativeAddressIsExecutable(elf, value))
            //     offset = (uint8_t *)outexecutable + value;
            //     write_process_form_sys(procpid, offset, , 8);
            // else
            //     offset = (uint8_t *)outwritable + value;
            write_process_form_sys(procpid, offset, &value, 8);
        }
    }

    return ELF_LOADER_RETURN_OK;
}

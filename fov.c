#include <windows.h>

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "onecore")

#define DEFAULT_FOV_MULTIPLIER 1.4f
#define ALLOCATION_GRANULARITY 0x10000ull
#define BRIDGE_REACH (INT32_MAX + 1ull - ALLOCATION_GRANULARITY)
#define PAGE_SIZE 0x1000
#define JMP_REL32 0xe9
#define NOP 0x90
#define VEX_OPCODE_SIZE 4
#define RIP_OPCODE_SIZE 3
#define RESOURCE_STORE_SIZE 3
#define SETTER_PREFIX_SIZE 7
#define JNZ_SHORT 0x75
#define CONFIG_KEY_MAX 31
#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

#define REAL_INPUT "\\\\.\\GLOBALROOT\\SystemRoot\\System32\\dinput8.dll"
#pragma comment(                                                               \
    linker, "/export:DirectInput8Create=" REAL_INPUT ".DirectInput8Create")

#define log_line(...)                                                          \
    do {                                                                       \
        if (log_file)                                                          \
            fprintf(log_file, __VA_ARGS__);                                    \
    } while (0)

#define expect(x)                                                              \
    do {                                                                       \
        if (!(x)) {                                                            \
            log_line("%s:%d: %s\n", __FILE__, __LINE__, #x);                   \
            return 0;                                                          \
        }                                                                      \
    } while (0)

static FILE *log_file;

struct image {
    unsigned char *base;
    IMAGE_NT_HEADERS64 *nt;
};

struct glacier_property {
    const char *name;
    uint64_t id;
    const void *type;
    uint64_t offset, flags;
    struct property_setter *setter;
    const void *getter;
};

#pragma pack(push, 1)
struct jump {
    unsigned char opcode;
    int32_t displacement;
};
struct vex_instruction {
    unsigned char opcode[VEX_OPCODE_SIZE];
    int32_t displacement;
};
struct property_setter {
    unsigned char prefix[SETTER_PREFIX_SIZE];
    int32_t adjustment;
    struct jump update;
};
struct bridge {
    struct vex_instruction load, multiply;
    struct jump back;
    float factor;
};
struct rip_reference {
    unsigned char opcode[RIP_OPCODE_SIZE];
    int32_t displacement;
};
struct letterbox_skip {
    unsigned char condition, distance;
    unsigned char store[RESOURCE_STORE_SIZE];
    struct jump exit;
};
struct unwind_info {
    unsigned char version : 3, flags : 5;
    unsigned char prolog_size, code_count, frame;
};
#pragma pack(pop)

struct config {
    float fov_multiplier;
    bool remove_black_bars;
};

static bool in_image(const struct image *image, const void *p, size_t size) {
    size_t rva = (uintptr_t)p - (uintptr_t)image->base;
    size_t limit = image->nt->OptionalHeader.SizeOfImage;
    return rva <= limit && size <= limit - rva;
}

static struct image open_image(void *base) {
    IMAGE_DOS_HEADER *dos = base;
    IMAGE_NT_HEADERS64 *nt = (void *)((unsigned char *)base + dos->e_lfanew);
    return (struct image){base, nt};
}

/* MSVC splits functions into unwind regions, so let's follow chained records
 * to the entry point */
static RUNTIME_FUNCTION *find_function(const struct image *image,
                                       const void *address) {
    DWORD64 base;
    RUNTIME_FUNCTION *function =
        RtlLookupFunctionEntry((DWORD64)address, &base, NULL);
    expect(function && base == (DWORD64)image->base);

    for (;;) {
        struct unwind_info *unwind =
            (void *)(image->base + function->UnwindData);
        if (!(unwind->flags & UNW_FLAG_CHAININFO))
            return function;

        USHORT *codes = (void *)(unwind + 1);
        function = (void *)&codes[(unwind->code_count + 1) & ~1];
    }
}

static unsigned char *find_letterbox(const struct image *image) {
    static const char label[] = "DrawLetterbox";

    /* Load DrawLetterbox into rdx. So we can handily use this to locate the
     * function that's drawing these annoying ass black bars.
     *
     * lea rdx, [rip+disp32] */
    static const unsigned char reference_opcode[] = {0x48, 0x8d, 0x15};

    /* The developers handily included a path that doesn't draw bars, so use
     * this to work backwards.
     *
     * mov qword ptr [rcx], rbx */
    static const unsigned char passthrough_store[] = {0x48, 0x89, 0x19};

    unsigned char *branch = NULL;
    unsigned matches = 0;
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(image->nt);
    for (unsigned s = 0; s < image->nt->FileHeader.NumberOfSections; ++s) {
        IMAGE_SECTION_HEADER *section = &sections[s];
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        unsigned char *code = image->base + section->VirtualAddress;
        size_t size = section->Misc.VirtualSize;

        for (size_t i = 0; i + sizeof(struct rip_reference) <= size; ++i) {
            struct rip_reference *reference = (void *)(code + i);
            if (memcmp(reference->opcode,
                       reference_opcode,
                       sizeof(reference_opcode)))
                continue;

            unsigned char *name =
                (unsigned char *)(reference + 1) + reference->displacement;
            if (!in_image(image, name, sizeof(label)) ||
                memcmp(name, label, sizeof(label)))
                continue;

            RUNTIME_FUNCTION *function = find_function(image, code + i);
            expect(function);

            unsigned char *entry = image->base + function->BeginAddress;
            size_t length = function->EndAddress - function->BeginAddress;
            for (size_t offset = 0;
                 offset + sizeof(struct letterbox_skip) <= length;
                 ++offset) {
                struct letterbox_skip *skip = (void *)(entry + offset);
                /* The branch skips the passthrough when drawing is enabled:
                 *
                 * jne draw_bars
                 * mov qword ptr [rcx], rbx
                 * jmp epilogue
                 * draw_bars: */
                if (skip->condition == JNZ_SHORT &&
                    skip->distance ==
                        sizeof(skip->store) + sizeof(skip->exit) &&
                    !memcmp(
                        skip->store, passthrough_store, sizeof(skip->store)) &&
                    skip->exit.opcode == JMP_REL32) {
                    branch = entry + offset;
                    ++matches;
                }
            }
        }
    }

    expect(matches == 1);
    return branch;
}

static struct vex_instruction *find_fov(const struct image *image) {
    static const char name[] = "m_FOVOverrideValue";

    /* The setter will copy the new FOV from [rdx] to [rcx], then move rcx back
     * from the field to the camera object. That then must agree with the field
     * offset in the reflection metadata
     *
     * mov eax, dword ptr [rdx]
     * mov dword ptr [rcx], eax
     * add rcx, imm32 */
    static const unsigned char setter_prefix[] = {
        0x8b, 0x02, 0x89, 0x01, 0x48, 0x81, 0xc1};

    /* Load the camera's FOV into xmm0. Find the read so that we can scale the
     * value without changing the stored FOV
     *
     * vmovss xmm0, dword ptr [rcx+disp32] */
    static const unsigned char load_opcode[] = {0xc5, 0xfa, 0x10, 0x81};

    const struct glacier_property *property = NULL;
    unsigned matches = 0;
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(image->nt);

    for (unsigned i = 0; i < image->nt->FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER *section = &sections[i];
        if (!(section->Characteristics & IMAGE_SCN_MEM_READ) ||
            (section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        unsigned char *start = image->base + section->VirtualAddress;
        size_t size = section->Misc.VirtualSize;

        for (size_t offset = 0; offset + sizeof(*property) <= size;
             offset += sizeof(void *)) {
            const struct glacier_property *candidate = (void *)(start + offset);
            if (in_image(image, candidate->name, sizeof(name)) &&
                !memcmp(candidate->name, name, sizeof(name))) {
                property = candidate;
                ++matches;
            }
        }
    }

    expect(matches == 1);

    struct property_setter *setter = property->setter;
    expect(in_image(image, setter, sizeof(*setter)));
    expect(!memcmp(setter->prefix, setter_prefix, sizeof(setter_prefix)));
    expect(setter->adjustment == -(int64_t)property->offset);

    /* The setter ends by jumping to the camera update function. Follow that
     * jump so we can limit our search for the FOV read to the code that is
     * gonna use it */
    expect(setter->update.opcode == JMP_REL32);
    unsigned char *update =
        (unsigned char *)(setter + 1) + setter->update.displacement;

    RUNTIME_FUNCTION *function = find_function(image, update);
    expect(function && image->base + function->BeginAddress == update);

    size_t length = function->EndAddress - function->BeginAddress;
    struct vex_instruction *site = NULL;
    matches = 0;
    for (size_t i = 0; i + sizeof(*site) <= length; ++i) {
        struct vex_instruction *load = (void *)(update + i);
        if (!memcmp(load->opcode, load_opcode, sizeof(load_opcode)) &&
            load->displacement == property->offset) {
            site = load;
            ++matches;
        }
    }

    expect(matches == 1);
    return site;
}

static struct bridge *make_bridge(const struct vex_instruction *site,
                                  float multiplier) {
    uintptr_t aligned = (uintptr_t)site & ~(ALLOCATION_GRANULARITY - 1);
    MEM_ADDRESS_REQUIREMENTS range = {
        .LowestStartingAddress = (void *)(aligned - BRIDGE_REACH),
        .HighestEndingAddress = (void *)(aligned + BRIDGE_REACH - 1),
    };
    MEM_EXTENDED_PARAMETER parameter = {
        .Type = MemExtendedParameterAddressRequirements,
        .Pointer = &range,
    };

    struct bridge *bridge = VirtualAlloc2(NULL,
                                          NULL,
                                          PAGE_SIZE,
                                          MEM_RESERVE | MEM_COMMIT,
                                          PAGE_READWRITE,
                                          &parameter,
                                          1);
    if (!bridge)
        return NULL;

    /* Repeat the original FOV load, multiply xmm0 by our nearby factor, then
     * jump back to the instruction after that load. That way, only the value
     * in the register changes.
     *
     * vmovss xmm0, dword ptr [rcx+field]
     * vmulss xmm0, xmm0, dword ptr [rip+disp32]
     * jmp after_original_load */
    *bridge = (struct bridge){
        .load = *site,
        .multiply = {{0xc5, 0xfa, 0x59, 0x05},
                     offsetof(struct bridge, factor) -
                         offsetof(struct bridge, back)},
        .back = {JMP_REL32,
                 (int32_t)((intptr_t)(site + 1) - (intptr_t)&bridge->factor)},
        .factor = multiplier,
    };

    DWORD old;
    if (!VirtualProtect(bridge, sizeof(*bridge), PAGE_EXECUTE_READ, &old))
        return NULL;
    FlushInstructionCache(GetCurrentProcess(), bridge, sizeof(*bridge));
    return bridge;
}

static bool write_code(void *address, const void *bytes, size_t size) {
    DWORD old;
    expect(VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old));

    memcpy(address, bytes, size);
    FlushInstructionCache(GetCurrentProcess(), address, size);

    DWORD ignored;
    VirtualProtect(address, size, old, &ignored);
    return true;
}

static bool scale_fov(const struct image *image, float multiplier) {
    struct vex_instruction *site = find_fov(image);
    if (!site)
        return false;

    struct bridge *bridge = make_bridge(site, multiplier);
    expect(bridge);

    struct jump jump = {
        JMP_REL32, (int32_t)((intptr_t)bridge - (intptr_t)site - sizeof(jump))};
    expect(write_code(site, &jump, sizeof(jump)));

    log_line("FOV multiplier %g; hook RVA 0x%zx\n",
             multiplier,
             (unsigned char *)site - image->base);
    return true;
}

static bool remove_black_bars(const struct image *image) {
    unsigned char *branch = find_letterbox(image);
    if (!branch)
        return false;

    /* Execution then continues into the path that skips the pass */
    const unsigned char disabled[] = {NOP, NOP};
    return write_code(branch, disabled, sizeof(disabled));
}

static HMODULE module;

static bool sibling_path(wchar_t path[MAX_PATH], const wchar_t *name) {
    DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    expect(length && length < MAX_PATH);

    wcsrchr(path, L'\\')[1] = L'\0';
    wcscat_s(path, MAX_PATH, name);
    return true;
}

static bool read_config(struct config *config) {
    wchar_t path[MAX_PATH];
    if (!sibling_path(path, L"FirstLightFOV.ini"))
        return false;

    FILE *file = _wfopen(path, L"r");
    if (!file) {
        expect(errno == ENOENT);
        return true;
    }

    char key[CONFIG_KEY_MAX + 1];
    float value;
    int fields;

    while ((fields = fscanf(file,
                            " %" STRINGIFY(CONFIG_KEY_MAX) "[^= \t\r\n] = %f",
                            key,
                            &value)) == 2) {
        if (!strcmp(key, "fov_multiplier") && isfinite(value) && value > 0)
            config->fov_multiplier = value;
        else if (!strcmp(key, "remove_black_bars") &&
                 (value == 0 || value == 1))
            config->remove_black_bars = value != 0;
        else
            break;
    }

    bool valid = fields == EOF && !ferror(file);
    fclose(file);
    expect(valid);
    return true;
}

static bool init_fixes(void *reserved) {
    /* Will fail if it's LoadLibrary(), which will cause us to spectacularly
     * explode */
    expect(reserved);

    struct config config = {DEFAULT_FOV_MULTIPLIER, true};
    struct image image = open_image(GetModuleHandleW(NULL));
    if (!read_config(&config))
        return false;

    scale_fov(&image, config.fov_multiplier);
    if (config.remove_black_bars && remove_black_bars(&image))
        log_line("Black bars disabled\n");
    return true;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    module = instance;
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH))
        return TRUE;

    if (_wcsicmp(wcsrchr(path, L'\\') + 1, L"007FirstLight.exe"))
        return TRUE;

    if (sibling_path(path, L"FirstLightFOV.log"))
        log_file = _wfopen(path, L"w");

    init_fixes(reserved);

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    return TRUE;
}

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
#define BRIDGE_REACH (INT32_MAX + 1ull - 2 * ALLOCATION_GRANULARITY)
#define PAGE_SIZE 0x1000
#define JMP_REL32 0xe9
#define CALL_REL32 0xe8
#define LEA_RAX_RIP {0x48, 0x8d, 0x05}
#define LEA_RCX_RIP {0x48, 0x8d, 0x0d}
#define LEA_RDX_RIP {0x48, 0x8d, 0x15}
#define STARTUP_CHECKPOINT "MainMenu"
#define STRING_LITERAL 0x80000000u
#define CALLBACK_PADDING_WORDS 2
#define RTTI_RELATIVE_SIGNATURE 1
#define JZ_SHORT 0x74
#define NOP 0x90
#define INT3 0xcc
#define VEX_OPCODE_SIZE 4
#define RIP_OPCODE_SIZE 3
#define RESOURCE_STORE_SIZE 3
#define SETTER_PREFIX_SIZE 7
#define BYTE_FIELD_OPCODE_SIZE 2
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

struct game_string {
    uint32_t length, reserved;
    const char *text;
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
struct checkpoint_bridge {
    struct rip_reference source;
    struct jump copy;
    struct game_string checkpoint;
};
struct checkpoint_copy {
    unsigned char opcode[RIP_OPCODE_SIZE];
    int8_t field;
    struct jump call;
};
struct availability_update {
    unsigned char compare[BYTE_FIELD_OPCODE_SIZE];
    int32_t read_field;
    unsigned char condition, distance;
    unsigned char store[BYTE_FIELD_OPCODE_SIZE];
    int32_t write_field;
};
#pragma pack(pop)

struct config {
    float fov_multiplier;
    bool remove_black_bars;
    bool auto_continue;
};

struct bound_function {
    void **vtable;
    uintptr_t method;
    intptr_t adjustment;
    void (*callback)(int);
    void *receiver; /* Just apply callback(result) if NULL */
};

enum callback_method {
    CALLBACK_COPY,
    CALLBACK_MOVE,
    CALLBACK_INVOKE,
    CALLBACK_METHODS,
};

struct completion {
    struct bound_function function;
    void *padding[CALLBACK_PADDING_WORDS];
    struct bound_function *target;
};

struct type_descriptor {
    const void *vtable, *reserved;
};

struct object_locator {
    uint32_t signature, offset, constructor_offset;
    uint32_t type, hierarchy, self;
};

static bool (*update_continue)(void *);
static void *(*destroy_continue)(void *, unsigned);
static void (*continue_game)(void *, void *);
static void *game_manager, *continue_provider;
static int32_t continue_offset;
static bool continue_pending;
static void **completion_vtable;

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

static void *find_data(const struct image *image, const void *bytes,
                       size_t length) {
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(image->nt);
    const unsigned char *needle = bytes;
    void *found = NULL;
    unsigned matches = 0;

    for (unsigned s = 0; s < image->nt->FileHeader.NumberOfSections; ++s) {
        IMAGE_SECTION_HEADER *section = &sections[s];
        if (!(section->Characteristics & IMAGE_SCN_MEM_READ) ||
            (section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        unsigned char *p = image->base + section->VirtualAddress;
        unsigned char *end = p + section->Misc.VirtualSize;
        for (; (p = memchr(p, needle[0], end - p)); ++p)
            if (length <= (size_t)(end - p) && !memcmp(p, bytes, length)) {
                found = p;
                ++matches;
            }
    }

    expect(matches == 1);
    return found;
}

static struct rip_reference *find_label_reference(const struct image *image,
                                                  const char *label,
                                                  const unsigned char *opcode) {
    const void *name = find_data(image, label, strlen(label) + 1);
    expect(name);
    struct rip_reference *found = NULL;
    unsigned matches = 0;
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(image->nt);

    /* lea reg, [rip+disp32] */
    for (unsigned s = 0; s < image->nt->FileHeader.NumberOfSections; ++s) {
        IMAGE_SECTION_HEADER *section = &sections[s];
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        unsigned char *code = image->base + section->VirtualAddress;
        for (size_t i = 0; i + sizeof(*found) <= section->Misc.VirtualSize;
             ++i) {
            struct rip_reference *reference = (void *)(code + i);
            if (!memcmp(reference->opcode, opcode, RIP_OPCODE_SIZE) &&
                (unsigned char *)(reference + 1) + reference->displacement ==
                    name) {
                found = reference;
                ++matches;
            }
        }
    }
    expect(matches == 1);
    return found;
}

static unsigned char *find_letterbox(const struct image *image) {
    /* Load DrawLetterbox into rdx. So we can handily use this to locate the
     * function that's drawing these annoying ass black bars.
     *
     * lea rdx, [rip+disp32] */
    static const unsigned char reference_opcode[] = LEA_RDX_RIP;

    /* The developers handily included a path that doesn't draw bars, so use
     * this to work backwards.
     *
     * mov qword ptr [rcx], rbx */
    static const unsigned char passthrough_store[] = {0x48, 0x89, 0x19};

    struct rip_reference *reference =
        find_label_reference(image, "DrawLetterbox", reference_opcode);
    expect(reference);
    RUNTIME_FUNCTION *function = find_function(image, reference);
    expect(function);

    unsigned char *entry = image->base + function->BeginAddress;
    size_t length = function->EndAddress - function->BeginAddress;
    unsigned char *branch = NULL;
    unsigned matches = 0;
    for (size_t offset = 0; offset + sizeof(struct letterbox_skip) <= length;
         ++offset) {
        struct letterbox_skip *skip = (void *)(entry + offset);
        /* The branch skips the passthrough when drawing is enabled:
         *
         * jne draw_bars
         * mov qword ptr [rcx], rbx
         * jmp epilogue
         * draw_bars: */
        if (skip->condition == JNZ_SHORT &&
            skip->distance == sizeof(skip->store) + sizeof(skip->exit) &&
            !memcmp(skip->store, passthrough_store, sizeof(skip->store)) &&
            skip->exit.opcode == JMP_REL32) {
            branch = entry + offset;
            ++matches;
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

static void *allocate_near(const void *site, const void *target) {
    uintptr_t low =
        min((uintptr_t)site, (uintptr_t)target) & ~(ALLOCATION_GRANULARITY - 1);
    uintptr_t high =
        max((uintptr_t)site, (uintptr_t)target) & ~(ALLOCATION_GRANULARITY - 1);
    /* The caller has to reach the bridge, and the bridge has to reach the
     * original function. Keep it within jump range of both ends.
     *
     * call bridge
     * bridge: ...
     * jmp original_target */
    MEM_ADDRESS_REQUIREMENTS range = {
        .LowestStartingAddress = (void *)(high - BRIDGE_REACH),
        .HighestEndingAddress = (void *)(low + BRIDGE_REACH - 1),
    };
    MEM_EXTENDED_PARAMETER parameter = {
        .Type = MemExtendedParameterAddressRequirements,
        .Pointer = &range,
    };

    return VirtualAlloc2(NULL,
                         NULL,
                         PAGE_SIZE,
                         MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE,
                         &parameter,
                         1);
}

static struct bridge *make_bridge(const struct vex_instruction *site,
                                  float multiplier) {
    struct bridge *bridge = allocate_near(site, site);
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

static bool in_code(const struct image *image, const void *address) {
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(image->nt);
    uintptr_t rva = (uintptr_t)address - (uintptr_t)image->base;

    for (unsigned i = 0; i < image->nt->FileHeader.NumberOfSections; ++i)
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            rva >= sections[i].VirtualAddress &&
            rva - sections[i].VirtualAddress < sections[i].Misc.VirtualSize)
            return true;
    return false;
}

static size_t function_end(const struct image *image,
                           const RUNTIME_FUNCTION *function) {
    size_t end = function->EndAddress;
    /* The first unwind region can be just the prologue. Keep the adjoining
     * regions too, as long as they chain back to the same function. */
    while (in_code(image, image->base + end)) {
        DWORD64 base;
        RUNTIME_FUNCTION *next =
            RtlLookupFunctionEntry((DWORD64)(image->base + end), &base, NULL);
        if (!next || base != (DWORD64)image->base || next->BeginAddress != end)
            break;
        RUNTIME_FUNCTION *owner = find_function(image, image->base + end);
        if (!owner || owner->BeginAddress != function->BeginAddress)
            break;
        end = next->EndAddress;
    }
    return end;
}

static void **find_vtable(const struct image *image, const char *name) {
    unsigned char *type = find_data(image, name, strlen(name) + 1);
    expect(type);
    type -= sizeof(struct type_descriptor);

    struct object_locator prefix = {.signature = RTTI_RELATIVE_SIGNATURE,
                                    .type = (uint32_t)(type - image->base)};
    struct object_locator *locator =
        find_data(image, &prefix, offsetof(struct object_locator, hierarchy));
    expect(locator && image->base + locator->self == (unsigned char *)locator);

    void **reference = find_data(image, &locator, sizeof(locator));
    return reference ? reference + 1 : NULL;
}

static unsigned char *find_virtual_pattern(const struct image *image,
                                           void **vtable, const void *bytes,
                                           size_t length, void ***method) {
    unsigned char *found = NULL;
    unsigned matches = 0;

    for (void **slot = vtable;
         in_image(image, slot, sizeof(*slot)) && in_code(image, *slot);
         ++slot) {
        DWORD64 base;
        RUNTIME_FUNCTION *function =
            RtlLookupFunctionEntry((DWORD64)*slot, &base, NULL);
        unsigned char *start = *slot, *end = start;
        if (function) {
            function = find_function(image, start);
            expect(function);
            start = image->base + function->BeginAddress;
            end = image->base + function_end(image, function);
        } else {
            /* Leaf methods don't need unwind records. The compiler pads the
             * space after them with breakpoints, so stop there instead. */
            while (in_code(image, end) && *end != INT3)
                ++end;
        }
        for (unsigned char *p = start; p + length <= end; ++p)
            if (!memcmp(p, bytes, length)) {
                found = p;
                if (method)
                    *method = slot;
                ++matches;
            }
    }

    expect(matches == 1);
    return found;
}

static void resumed(int result) { (void)result; }

static bool resume_latest(void *provider) {
    bool changed = update_continue(provider);
    if (!continue_provider)
        continue_provider = provider;

    if (continue_pending && provider == continue_provider &&
        *(bool *)((unsigned char *)provider + continue_offset)) {
        /* Loading can update the UI before returning */
        continue_pending = false;
        struct completion completion = {
            .function = {.vtable = completion_vtable, .callback = resumed},
        };
        completion.target = &completion.function;
        continue_game(game_manager, &completion);
    }
    return changed;
}

static void *leave_startup(void *provider, unsigned flags) {
    if (provider == continue_provider)
        continue_pending = false;
    return destroy_continue(provider, flags);
}

static void **find_completion_vtable(const struct image *image,
                                     const RUNTIME_FUNCTION *function,
                                     size_t *out_end) {
    size_t end = function_end(image, function);
    void **table = NULL;

    /* lea rax, [rip+callback_vtable] */
    static const unsigned char callback_opcode[] = LEA_RAX_RIP;
    unsigned callback_matches = 0;
    for (size_t i = function->BeginAddress;
         i + sizeof(struct rip_reference) <= end;
         ++i) {
        struct rip_reference *reference = (void *)(image->base + i);
        if (memcmp(reference->opcode, callback_opcode, sizeof(callback_opcode)))
            continue;
        void **candidate = (void *)((unsigned char *)(reference + 1) +
                                    reference->displacement);
        if (in_image(image, candidate, CALLBACK_METHODS * sizeof(*candidate)) &&
            in_code(image, candidate[CALLBACK_COPY]) &&
            candidate[CALLBACK_COPY] == candidate[CALLBACK_MOVE] &&
            in_code(image, candidate[CALLBACK_INVOKE])) {
            table = candidate;
            *out_end = i + sizeof(*reference);
            ++callback_matches;
        }
    }
    expect(callback_matches == 1);

    /* With no object bound, the game's invoker reads the function pointer and
     * passes the result to it, so let's check that it agrees with our layout.
     *
     * mov r8, qword ptr [rcx+receiver]
     * ...
     * mov rax, qword ptr [rcx+callback]
     * mov ecx, edx
     * jmp rax */
    const unsigned char callback_load[] = {
        0x48, 0x8b, 0x41, offsetof(struct bound_function, callback)};
    const unsigned char receiver_load[] = {
        0x4c, 0x8b, 0x41, offsetof(struct bound_function, receiver)};
    void **invoke_slot = NULL;
    expect(find_virtual_pattern(
        image, table, callback_load, sizeof(callback_load), &invoke_slot));
    expect(!memcmp(*invoke_slot, receiver_load, sizeof(receiver_load)));

    return table;
}

static struct jump *find_checkpoint_copy(const struct image *image,
                                         const void *setting) {
    /* lea rdx, [rax+default_checkpoint]
     * call copy_string */
    static const unsigned char source_opcode[] = {0x48, 0x8d, 0x50};
    RUNTIME_FUNCTION *function = find_function(image, setting);
    expect(function);
    struct jump *copy = NULL;
    unsigned matches = 0;
    size_t end = function_end(image, function);
    for (size_t i = function->BeginAddress;
         i + sizeof(struct checkpoint_copy) <= end;
         ++i) {
        struct checkpoint_copy *candidate = (void *)(image->base + i);
        if (!memcmp(candidate->opcode, source_opcode, sizeof(source_opcode)) &&
            candidate->call.opcode == CALL_REL32) {
            copy = &candidate->call;
            ++matches;
        }
    }
    expect(matches == 1);
    return copy;
}

static bool skip_startup(const struct image *image) {
    void **availability =
        find_vtable(image, ".?AVZGameManagerHasContinue@JSONTemplate@@");
    void **action =
        find_vtable(image, ".?AVZGameManagerContinue@JSONTemplate@@");
    static const unsigned char setting_opcode[] = LEA_RAX_RIP;
    static const unsigned char boot_opcode[] = LEA_RDX_RIP;
    struct rip_reference *setting =
        find_label_reference(image, "INITIAL_CHECKPOINT", setting_opcode);
    struct rip_reference *boot =
        find_label_reference(image, "BootDontWaitForInput", boot_opcode);
    expect(availability && action && setting && boot);

    /* The developers were kind enough to have a path for continuing without
     * having to go through the rigamarole of keyboard input. So let's remove
     * the branch to go that way
     *
     * test sil, sil
     * je wait_for_input */
    static const unsigned char wait_test[] = {0x40, 0x84, 0xf6, JZ_SHORT};
    RUNTIME_FUNCTION *boot_function = find_function(image, boot);
    expect(boot_function);
    unsigned char *wait = NULL;
    unsigned wait_matches = 0;
    size_t boot_end = function_end(image, boot_function);
    for (size_t i = boot_function->BeginAddress;
         i + sizeof(wait_test) + sizeof(int8_t) <= boot_end;
         ++i)
        if (!memcmp(image->base + i, wait_test, sizeof(wait_test))) {
            wait = image->base + i + sizeof(wait_test) - 1;
            ++wait_matches;
        }
    expect(wait_matches == 1);

    /* cmp byte ptr [rcx+field], al
     * je unchanged
     * mov byte ptr [rcx+field], al */
    static const unsigned char compare[] = {0x38, 0x81};
    void **update_slot = NULL;
    unsigned char *member = find_virtual_pattern(
        image, availability, compare, sizeof(compare), &update_slot);
    expect(member);
    const struct availability_update *update = (const void *)member;
    static const unsigned char store[] = {0x88, 0x81};
    expect(in_image(image, update, sizeof(*update)) &&
           update->condition == JZ_SHORT &&
           !memcmp(update->store, store, sizeof(store)) &&
           update->read_field == update->write_field);
    continue_offset = update->read_field;
    expect(continue_offset > 0);

    /* Follow the code behind the continue button.
     *
     * call continue_handler
     * xor eax, eax
     * add rsp, 28h
     * ret */
    static const unsigned char result[] = {
        0x33, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3};
    unsigned char *done =
        find_virtual_pattern(image, action, result, sizeof(result), NULL);
    expect(done);
    struct jump *call = (void *)(done - sizeof(*call));
    expect(call->opcode == CALL_REL32);
    unsigned char *handler = (unsigned char *)(call + 1) + call->displacement;
    RUNTIME_FUNCTION *function = find_function(image, handler);
    expect(function && image->base + function->BeginAddress == handler);

    size_t callback_built;
    completion_vtable =
        find_completion_vtable(image, function, &callback_built);
    expect(completion_vtable);

    /* Ask the game manager to load the latest save. The dialog lookup before
     * this uses the same instructions, so start after the callback is built.
     *
     * lea rcx, [rip+game_manager]
     * call load_latest_save */
    static const unsigned char manager_opcode[] = LEA_RCX_RIP;
    struct rip_reference *manager = NULL;
    struct jump *load = NULL;
    unsigned manager_matches = 0;
    size_t end = function_end(image, function);
    for (size_t i = callback_built; i + sizeof(*manager) + sizeof(*load) <= end;
         ++i) {
        struct rip_reference *candidate = (void *)(image->base + i);
        struct jump *next = (void *)(candidate + 1);
        if (!memcmp(
                candidate->opcode, manager_opcode, sizeof(manager_opcode)) &&
            next->opcode == CALL_REL32) {
            manager = candidate;
            load = next;
            ++manager_matches;
        }
    }
    expect(manager_matches == 1);
    game_manager = (unsigned char *)(manager + 1) + manager->displacement;
    void *loader = (unsigned char *)(load + 1) + load->displacement;
    expect(in_image(image, game_manager, 1) && in_code(image, loader));

    struct jump *copy = find_checkpoint_copy(image, setting);
    expect(copy);
    unsigned char *target = (unsigned char *)(copy + 1) + copy->displacement;
    expect(in_code(image, target));
    struct checkpoint_bridge *bridge = allocate_near(copy, target);
    expect(bridge);

    /* lea rdx, [rip+checkpoint]
     * jmp copy_string */
    *bridge = (struct checkpoint_bridge){
        .source = {LEA_RDX_RIP,
                   offsetof(struct checkpoint_bridge, checkpoint) -
                       sizeof(struct rip_reference)},
        .copy = {JMP_REL32,
                 (int32_t)((intptr_t)(copy + 1) + copy->displacement -
                           (intptr_t)&bridge->checkpoint)},
        .checkpoint = {STRING_LITERAL | (sizeof(STARTUP_CHECKPOINT) - 1),
                       0,
                       STARTUP_CHECKPOINT},
    };
    DWORD old;
    expect(VirtualProtect(bridge, sizeof(*bridge), PAGE_EXECUTE_READ, &old));
    FlushInstructionCache(GetCurrentProcess(), bridge, sizeof(*bridge));

    memcpy(&update_continue, update_slot, sizeof(update_continue));
    memcpy(&destroy_continue, availability, sizeof(destroy_continue));
    memcpy(&continue_game, &loader, sizeof(continue_game));
    bool (*hook)(void *) = resume_latest;
    void *(*destroy)(void *, unsigned) = leave_startup;
    struct jump redirect = {CALL_REL32,
                            (int32_t)((intptr_t)bridge - (intptr_t)(copy + 1))};
    expect(write_code(availability, &destroy, sizeof(destroy)));
    expect(write_code(update_slot, &hook, sizeof(hook)));
    continue_pending = true;
    expect(write_code(copy, &redirect, sizeof(redirect)));
    const unsigned char no_wait[] = {NOP, NOP};
    expect(write_code(wait, no_wait, sizeof(no_wait)));
    log_line("Startup shortcut enabled\n");
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

static bool read_config(const wchar_t *path, struct config *config) {
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
        else if (!strcmp(key, "auto_continue") && (value == 0 || value == 1))
            config->auto_continue = value != 0;
        else
            break;
    }

    bool valid = fields == EOF && !ferror(file);
    fclose(file);
    expect(valid);
    return true;
}

static bool init_fixes(const wchar_t *config_path, void *reserved) {
    /* Will fail if it's LoadLibrary(), which will cause us to spectacularly
     * explode */
    expect(reserved);

    struct config config = {DEFAULT_FOV_MULTIPLIER, true, true};
    struct image image = open_image(GetModuleHandleW(NULL));
    if (!read_config(config_path, &config))
        return false;

    scale_fov(&image, config.fov_multiplier);
    if (config.remove_black_bars && remove_black_bars(&image))
        log_line("Black bars disabled\n");
    if (config.auto_continue)
        skip_startup(&image);
    return true;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance;
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH))
        return TRUE;

    wchar_t *name = wcsrchr(path, L'\\') + 1;
    if (_wcsicmp(name, L"007FirstLight.exe"))
        return TRUE;

    wcscpy(name, L"FirstLightFOV.log");
    log_file = _wfopen(path, L"w");

    wcscpy(name, L"FirstLightFOV.ini");
    init_fixes(path, reserved);

    if (log_file)
        fclose(log_file);
    return TRUE;
}

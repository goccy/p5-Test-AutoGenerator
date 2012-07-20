#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include <iconv.h>

/*
typedef enum {
	SVt_NULL,	// 0
	SVt_BIND,	// 1
	SVt_IV,		// 2
	SVt_NV,		// 3
	// RV was here, before it was merged with IV.
	SVt_PV,		// 4
	SVt_PVIV,	// 5
	SVt_PVNV,	// 6
	SVt_PVMG,	// 7
	SVt_REGEXP,	// 8
	// PVBM was here, before BIND replaced it.
	SVt_PVGV,	// 9
	SVt_PVLV,	// 10
	SVt_PVAV,	// 11
	SVt_PVHV,	// 12
	SVt_PVCV,	// 13
	SVt_PVFM,	// 14
	SVt_PVIO,	// 15
	SVt_LAST	// keep last in enum. used to size arrays
} svtype;
*/

typedef enum {
	BLACK = 30,
	RED,
	GREEN,
	YELLOW,
	BLUE,
	MAGENTA,
	SYAN,
	GRAY,
	DEFAULT,
	WHITE,
} ANSIColor;

#define CHANGE_COLOR(color) fprintf(stderr, "\x1b[%dm", color)

#ifndef LOCALE
#define LOCALE "EUC-JP"
#endif

#ifdef DEBUG_MODE
#define DBG_PL(fmt, ...) {                      \
        fprintf(stderr, fmt, ## __VA_ARGS__);	\
        fprintf(stderr, "\n");                  \
    }
#else
#define DBG_PL(fmt, ...) {}
#endif
typedef enum {
    TYPE_Null = SVt_NULL,
    TYPE_Bind = SVt_BIND,
    TYPE_Int = SVt_IV,
    TYPE_Double = SVt_NV,
    TYPE_String = SVt_PV,
    TYPE_PtrInt = SVt_PVIV,
    TYPE_PtrDouble = SVt_PVNV,
    TYPE_Object = SVt_PVMG,
    TYPE_Regex = SVt_REGEXP,
    TYPE_Glob = SVt_PVGV,
    TYPE_PVLV = SVt_PVLV,
    TYPE_Array = SVt_PVAV,
    TYPE_Hash = SVt_PVHV,
    TYPE_Code = SVt_PVCV,
    TYPE_FM = SVt_PVFM,
    TYPE_IO = SVt_PVIO,
    L_TOP,
    TYPE_List = 18,
} PerlType;

#ifndef bool
typedef bool int
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#define KB 1024
#define MB KB * KB
#define MAX_CWB_SIZE 1 * MB
#define MAX_METHOD_NUM 4096
#define MAX_CALLSTACK_SIZE 4096
#define MAX_ARGS_NUM 64
#define MAX_FILE_NAME_SIZE 64
#define MAX_MACHINE_STACK_SIZE 1000
#define XS_ERROR_TEXT "# [cannot trace] XS MODULE"
#define TRACE_ERROR_TEXT "# [cannot trace] TOO LARGE SIZE"

typedef struct _FastSerializer {
    char *(*serialize)(struct _FastSerializer *fs, SV *v);
} FastSerializer;

typedef struct _VirtualCallStack {
    /* save object information */
    SV *v; /* current object */
    void *ret_addr; /* return address */
    /* save loop information */
    SV **a; /* current array objs (for array) */
    SV *hash_v;
    HE *next;
    int i; /* current item num (for array, hash) */
    int j; /* current serialize num (for hash) */
    int size; /* max item size (for array, hash) */
    int max_size; /* max search num (for hash) */
} VirtualCallStack;

typedef struct _CallFlow {
    const char *from_stash;
    const char *from;
    const char *to_stash;
    const char *to;
    const char *ret;
    bool is_xs;
    PerlType ret_type;
    struct _CallFlow *next;
    char *(*serializeObject)(struct _CallFlow *cf, SV *sv);
    void (*setReturnValue)(struct _CallFlow *cf, char *ret_value);
    void (*free)(struct _CallFlow *cf);
} CallFlow;

typedef struct _Method {
    const char *stash;
    const char *subname;
    const char *name;
    const char *args;
    const char *ret;
    bool args_error;
    PerlType ret_type;
    CallFlow *cfs;
    struct _Method *next;
    void (*addCallFlow)(struct _Method *mtd, CallFlow *cf);
    void (*setArgs)(struct _Method *mtd, char *args);
    bool (*existsCallFlow)(struct _Method *mtd, CallFlow *cf);
    void (*free)(struct _Method *mtd);
} Method;

typedef struct _Package {
    const char *name;
    const char **lib_paths;
    int lib_num;
    bool has_constructor;
    Method *mtds;
    struct _Package *next;
    void (*addMethod)(struct _Package *pkg, Method *mtd);
    bool (*existsLibrary)(struct _Package *pkg, const char *path);
    void (*addLibraryPath)(struct _Package *pkg, const char *path);
    void (*free)(struct _Package *pkg);
} Package;

typedef struct _TestCodeGenerator {
    FastSerializer *fs;
    Package *pkgs;
    int lib_num;
    Package *(*getMatchedPackage)(struct _TestCodeGenerator *tcg, const char *pkg_name);
    void (*addPackage)(struct _TestCodeGenerator *tcg, Package *pkg);
    void (*gen)(struct _TestCodeGenerator *tcg);
    void (*free)(struct _TestCodeGenerator *tcg);
} TestCodeGenerator;

extern char *cwb;
extern int cwb_idx;
extern jmp_buf jbuf;
extern void *safe_malloc(size_t size);
extern void safe_free(void *ptr, size_t size);
extern int leaks(void);
extern bool match(const char *from, const char *to);
extern bool find(const char *targ, char ch);
extern void write_space(FILE *fp, int space_num, bool comment_out_flag);
extern void write_cwb(char *buf);
extern FastSerializer *new_FastSerializer(void);

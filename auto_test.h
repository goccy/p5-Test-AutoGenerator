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

typedef enum {
    TYPE_Int = SVt_IV,
    TYPE_Double = SVt_NV,
    TYPE_String = SVt_PV,
    TYPE_Array = SVt_PVAV,
    TYPE_Hash = SVt_PVHV,
    TYPE_Object = SVt_PVMG,
    TYPE_Code = SVt_PVCV,
    TYPE_List = 17,
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
#define MAX_MACHINE_STACK_SIZE 20000

typedef struct String_ {
    size_t len;
    char *s;
} String;

typedef struct _CallFlow {
    const char *from_stash;
    const char *from;
    const char *to_stash;
    const char *to;
    const char *ret;
    PerlType ret_type;
    struct _CallFlow *next;
    char *(*serializeObject)(struct _CallFlow *cf, SV *sv);
    void (*setReturnValue)(struct _CallFlow *cf, char *ret_value);
} CallFlow;

typedef struct _Method {
    const char *stash;
    const char *subname;
    const char *name;
    const char **args;
    const char *ret;
    int args_size;
    PerlType ret_type;
    CallFlow *cfs;
    struct _Method *next;
    void (*addCallFlow)(struct _Method *mtd, CallFlow *cf);
    void (*setArgs)(struct _Method *mtd, char *args);
    bool (*existsCallFlow)(struct _Method *mtd, CallFlow *cf);
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
} Package;

typedef struct _Library {
    const char *path;
    const char *name;
} Library;

typedef struct _TestCodeGenerator {
    Package *pkgs;
    Library **libs;
    int lib_num;
    Package *(*getMatchedPackage)(struct _TestCodeGenerator *tcg, const char *pkg_name);
    void (*addPackage)(struct _TestCodeGenerator *tcg, Package *pkg);
    const char *(*getLibraryPath)(struct _TestCodeGenerator *tcg, const char *libname);
    bool (*existsLibrary)(struct _TestCodeGenerator *tcg, const char *libname);
    void (*gen)(struct _TestCodeGenerator *tcg);
} TestCodeGenerator;

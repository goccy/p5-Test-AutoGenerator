#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include <iconv.h>
#include <vector>
#include <string>
#include <map>
#include <assert.h>
#include <stdarg.h>

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
#define EOL '\0'

#define MAX_HASH_SIZE 512

class CallFlow;
class Method;
class Package;

template<typename T>
class List : public std::vector<T> {
public:
	void add(T v) { this->push_back(v); }
	void dump(void) {
		typename std::vector<T>::iterator it = this->begin();
		while (it != this->end()) {
			T v = *it;
			v->dump();
			it++;
		}
	}
};

template<typename T>
class Map : public std::map<std::string,T> {
public:
	void add(std::pair<std::string,T> v) {
		this->insert(v);
	}
	T get(std::string key) {
		return this->find(key)->second;
	}
	bool exists(std::string key) {
		return (this->find(key) != this->end()) ? true : false;
	}
	void dump(void) {
		typename std::map<std::string, T>::iterator it;
		it = this->begin();
		while (it != this->end()) {
			T v = it->second;
			v->dump();
			it++;
		}
	}
};

typedef List<CallFlow *> CallFlowList;
typedef List<Method *>  MethodList;
typedef Map<CallFlowList *> CallFlowMap;
typedef Map<MethodList *> MethodMap;
typedef Map<Package *> PackageMap;
typedef Map<const char *> LibraryMap;

class FastSerializer {
public:
	FastSerializer(void);
	char *serialize(SV *v);
};

typedef struct _VirtualCallStack {
public:
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

class CallFlow {
public:
	const char *from_stash;
	const char *from;
	const char *to_stash;
	const char *to;
	const char *args;
	const char *ret;
	const char *flow_raw_format;
	bool is_xs;
	PerlType ret_type;

	CallFlow(const char *from_stash, const char *from, const char *to_stash, const char *to);
	~CallFlow(void);
	void dump(void);
	void setReturnValue(char *ret_value, PerlType type);
};

class Method {
public:
	const char *stash;
	const char *subname;
	const char *name;
	const char *args;
	const char *ret;
	PerlType ret_type;
	CallFlowMap *cfs;

	Method(const char *name, const char *stash, const char *subname);
	~Method(void);
	void dump(void);
	void addCallFlow(CallFlow *flow);
	bool existsCallFlow(CallFlow *flow);
	void setReturnValue(const char *ret_value, PerlType type);
};

class Package {
public:
	const char *name;
	int lib_num;
	bool has_constructor;
	LibraryMap *libs;
	MethodMap *mtds;

	Package(const char *pkg_name);
	~Package(void);
	void dump(void);
	Method *getMethod(const char *mtd_name);
	void addMethod(Method *mtd);
	bool existsLibrary(const char *path);
	void addLibraryPath(const char *path);
};

class TestCodeGenerator {
public:
	FastSerializer *fs;
	PackageMap *pkgs;
	int lib_num;

	TestCodeGenerator(void);
	~TestCodeGenerator(void);
	bool existsPackage(const char *pkg_name);
	Package *getPackage(const char *pkg_name);
	Package *addPackage(Package *pkg);
	void dump(void);
	void gen(void);
};

extern char *cwb;
extern int cwb_idx;
extern jmp_buf jbuf;
extern void *safe_malloc(size_t size);
extern void safe_free(void *ptr, size_t size);
extern const char *safe_sprintf(const char *fmt, ...);
extern const char *strclone(const char *base);
extern int leaks(void);
extern bool match(const char *from, const char *to);
extern bool find(const char *targ, char ch);
extern void write_space(FILE *fp, int space_num, bool comment_out_flag);
extern void write_cwb(const char *buf);

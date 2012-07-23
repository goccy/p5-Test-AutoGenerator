#include "auto_test.h"

static VirtualCallStack *callstack = NULL;
static VirtualCallStack *callstack_top = NULL;
VirtualCallStack *new_VirtualCallStack(void)
{
    VirtualCallStack *callstack = (VirtualCallStack *)safe_malloc(MAX_CALLSTACK_SIZE * sizeof(VirtualCallStack));
    return callstack;
}

static char buf[32] = {0};
#define DEREF(v) v->sv_u.svu_rv
#define L(op) L_##op
#define DISPATCH_INIT() do {                    \
        callstack = callstack_top;              \
        callstack->v = v_;                      \
        callstack->ret_addr = &&L_END;          \
        (callstack+1)->ret_addr = &&L_END;      \
    } while (0)

#define DISPATCH_TOP() L(TOP) :; v_ = callstack->v
#define DISPATCH_END() L(END) :;

#define CASE(type) L(type) :
#define DISPATCH_TYPE(T) goto *jmp_table[T]
#define FAST_RETURN() goto *callstack->ret_addr

#ifdef STACK_UNLIMITED_MODE
#define DO_EXCEPTION() do {                                             \
        void *tmp = realloc(callstack, callstack_idx * 2 * sizeof(VirtualCallStack)); \
        if (!tmp) {                                                     \
            fprintf(stderr, "ERROR!!: cannot allocate from heap\n");      \
            longjmp(jbuf, 1);                                           \
            memset(cwb, 0, MAX_CWB_SIZE);                               \
            cwb_idx = 0;                                                \
        } else {                                                        \
            callstack = tmp;                                            \
        }                                                               \
    } while (0)
#else
#define DO_EXCEPTION() do {                     \
        longjmp(jbuf, 1);                       \
        memset(cwb, 0, MAX_CWB_SIZE);           \
        cwb_idx = 0;                            \
    } while (0)
#endif

#define RECURSIVE_CALL_byArray(_a, _i, _size) do {  \
        if (callstack_idx > MAX_CALLSTACK_SIZE) {   \
            DO_EXCEPTION();                         \
        }                                           \
        callstack_idx++;                            \
        callstack++;                                \
        callstack->ret_addr = &&L_ARRAY_AFTER;      \
        callstack->a = _a;                          \
        callstack->i = _i;                          \
        callstack->size = _size;                    \
        goto *jmp_table[L_TOP];                     \
    L_ARRAY_AFTER:;                                 \
        _a = callstack->a;                          \
        _i = callstack->i;                          \
        _size = callstack->size;                    \
        callstack--;                                \
        callstack_idx--;                            \
    } while (0)

#define CALL(array, _vv, _next, _sv, _i, _j, _size, _max_size, TO, FROM) do { \
        if (callstack_idx > MAX_CALLSTACK_SIZE) {                       \
            DO_EXCEPTION();                                             \
        }                                                               \
        callstack_idx++;                                                \
        callstack++;                                                    \
        callstack->ret_addr = &&L_##FROM##AFTER;                        \
        callstack->a = array;                                           \
        callstack->hash_v = _vv;                                        \
        callstack->next = _next;                                        \
        callstack->i = _i;                                              \
        callstack->j = _j;                                              \
        callstack->size = _size;                                        \
        callstack->max_size = _max_size;                                \
        callstack->v = _sv;                                             \
        goto *jmp_table[TO];                                            \
    L_##FROM##AFTER:                                                    \
        _sv = callstack->v;                                             \
        array = callstack->a;                                           \
        _vv = callstack->hash_v;                                        \
        _next = callstack->next;                                        \
        _i = callstack->i;                                              \
        _j = callstack->j;                                              \
        _size = callstack->size;                                        \
        _max_size = callstack->max_size;                                \
        callstack--;                                                    \
        callstack_idx--;                                                \
    } while (0)

#define FastSerializer_serializeIntObject(v) do {   \
        int ivalue = SvIVX(v);                      \
        snprintf(buf, 32, "%d", ivalue);            \
        write_cwb(buf);                             \
        memset(buf, 0, 32);                         \
    } while (0)

#define FastSerializer_serializeIntPtrObject(v) do {    \
        char *ptr = v->sv_u.svu_pv;                     \
        if (ptr) {                                      \
            snprintf(buf, 32, "%d", atoi(ptr));         \
        } else {                                        \
            snprintf(buf, 32, "0");                     \
        }                                               \
        write_cwb(buf);                                 \
        memset(buf, 0, 32);                             \
    } while (0)

#define FastSerializer_serializeDoubleObject(v) do {    \
        double dvalue = SvNVX(v);                       \
        snprintf(buf, 32, "%f", dvalue);                \
        write_cwb(buf);                                 \
        memset(buf, 0, 32);                             \
    } while (0)

#define FastSerializer_serializeDoublePtrObject(v) do { \
        char *ptr = v->sv_u.svu_pv;                     \
        if (ptr) {                                      \
            if (find(ptr, '.')) {                       \
                snprintf(buf, 32, "%f", atof(ptr));     \
            } else if (match(ptr, "")) {                \
                snprintf(buf, 32, "\"\"");              \
            } else {                                    \
                snprintf(buf, 32, "%d", atoi(ptr));     \
            }                                           \
        } else {                                        \
            snprintf(buf, 32, "''");                    \
        }                                               \
        write_cwb(buf);                                 \
        memset(buf, 0, 32);                             \
    } while (0)

#define FastSerializer_serializeStringObject(v) do {    \
        char *svalue = SvPVX(v);                        \
        if (svalue) {                                   \
            size_t len = strlen(svalue) + 1;            \
            size_t size = len;                          \
            char sout[size];                            \
            memset(sout, 0, size);                      \
            char *ptr_in  = svalue;                     \
            char *ptr_out = sout;                       \
            iconv_t ic = iconv_open("EUC-JP", LOCALE);  \
            iconv(ic, &ptr_in, &len, &ptr_out, &len);   \
            iconv_close(ic);                            \
            char buf[size + 2];                         \
            memset(buf, 0, size + 2);                   \
            snprintf(buf, size + 2, "\"%s\"", sout);    \
            write_cwb(buf);                             \
        } else {                                        \
            write_cwb("''");                            \
        }                                               \
    } while (0)

#define FastSerializer_serializeArrayObject(v) do {                     \
        SV *vv = NULL;                                                  \
        HE *next = NULL;                                                \
        int i, size = av_len((AV *)v);                                  \
        int j = 0;                                                      \
        int max_size = 0;                                               \
        SV **a = v->sv_u.svu_array;                                     \
        if (a) {                                                        \
            write_cwb("[");                                             \
            for (i = 0; i <= size; i++) {                               \
                SV *sv = a[i];                                          \
                if (sv) {CALL(a, vv, next, sv, i, j, size, max_size, L_TOP, TYPE_Array);} \
                if (i != size) write_cwb(", ");                         \
            }                                                           \
            write_cwb("]");                                             \
        } else {                                                        \
            write_cwb("undef");                                         \
        }                                                               \
    } while (0)

#define FastSerializer_serializeHashObject(v) do {                      \
        write_cwb("{");                                                 \
        XPVHV* xhv = (XPVHV*)SvANY(v);                                  \
        int i, j = 0;                                                   \
        int size = xhv->xhv_keys;                                       \
        int max_size = xhv->xhv_max;                                    \
        SV **a = NULL;                                                  \
        SV *vv = NULL;                                                  \
        if (size > 0) {                                                 \
            for (i = 0; i <= max_size; i++) {                           \
                HE **entries = v->sv_u.svu_hash;                        \
                HE *he = entries[i];                                    \
                if (he) {                                               \
                    char *key = he->hent_hek->hek_key;                  \
                    size_t len = strlen(key) + 1;                       \
                    char buf[len + 2];                                  \
                    memset(buf, 0, len + 2);                            \
                    snprintf(buf, len + 2, "\"%s\"", key);              \
                    write_cwb(buf);                                     \
                    write_cwb(" => ");                                  \
                    vv = he->he_valu.hent_val;                          \
                    CALL(a, v, he, vv, i, j, size, max_size, L_TOP, HE); \
                    entries = v->sv_u.svu_hash;                         \
                    j++;                                                \
                    if (j != size) write_cwb(", ");                     \
                    HE *next = entries[i]->hent_next;                   \
                    while (next) {                                      \
                        char *key = next->hent_hek->hek_key;            \
                        size_t len = strlen(key) + 1;                   \
                        char buf[len + 2];                              \
                        memset(buf, 0, len + 2);                        \
                        snprintf(buf, len + 2, "\"%s\"", key);          \
                        write_cwb(buf);                                 \
                        write_cwb(" => ");                              \
                        vv = next->he_valu.hent_val;                    \
                        CALL(a, v, next, vv, i, j, size, max_size, L_TOP, NEXT); \
                        j++;                                            \
                        if (j != size) write_cwb(", ");                 \
                        next = next->hent_next;                         \
                    }                                                   \
                }                                                       \
            }                                                           \
        }                                                               \
        write_cwb("}");                                                 \
    } while (0)

#define FastSerializer_serializeCodeObject(v) do {                  \
        HV *stash_ = CvSTASH((CV *)v);                              \
        if (!stash_) FAST_RETURN();                                      \
        char *stash_name = HvNAME(stash_);                          \
        char *func_name = GvNAME(CvGV((CV *)v));                    \
        size_t stash_size = strlen(stash_name);                     \
        size_t func_size = strlen(func_name);                       \
        if (stash_size == 4 && !strncmp(stash_name, "main", 4)) {   \
            char buf[func_size + 8];                                \
            sprintf(buf, "\\&%s", func_name);                       \
            write_cwb(buf);                                         \
        } else {                                                    \
            char buf[stash_size + func_size + 8];                   \
            sprintf(buf, "\\&%s::%s", stash_name, func_name);       \
            write_cwb(buf);                                         \
        }                                                           \
    } while (0)

#define FastSerializer_serializeGlobObject(v) do {                      \
        HEK *hek = v->sv_u.svu_gp->gp_egv->sv_any->xiv_u.xivu_namehek;  \
        char *glob = hek->hek_key;                                      \
        size_t glob_size = hek->hek_len;                                \
        char buf[glob_size + 1];                                        \
        sprintf(buf, "*%s", glob);                                      \
        write_cwb(buf);                                                 \
    } while (0)

#define FastSerializer_serializeLVObject(v) do {                    \
        XPVLV *xlv = (XPVLV *)v->sv_any;                            \
        SV *xlv_targ = xlv->xlv_targ;                               \
        SV **a = NULL;                                              \
        SV *he = NULL;                                              \
        HE *next = NULL;                                            \
        int i = 0;                                                  \
        int j = 0;                                                  \
        int size = 0;                                               \
        int max_size = 0;                                           \
        switch (LvTYPE(v)) {                                        \
        case 'y':                                                   \
            if (xlv->xlv_targ) CALL(a, he, next, xlv_targ, i, j, size, max_size, L_TOP, TYPE_LV); \
            break;                                                  \
        case 't': /* tie */                                         \
        case 'T': /* tied HE */                                     \
        case 'k': /* keys */                                        \
        case '.': /* pos */                                         \
        case 'x': /* substr */                                      \
        case 'v': /* vec */                                         \
        default:                                                    \
            write_cwb("undef");                                     \
            break;                                                  \
        }                                                           \
    } while (0)

#define FastSerializer_serializeBlessedObject(v) do {   \
        int i = 0;                                      \
        int j = 0;                                      \
        int size = 0;                                   \
        int max_size = 0;                               \
        SV **a = NULL;                                  \
        SV *he = NULL;                                  \
        HE *next = NULL;                                \
        if (SvTYPE(v) != TYPE_Hash) {                   \
            write_cwb("undef");                         \
            FAST_RETURN();                              \
        }                                               \
        write_cwb("bless (");                           \
        CALL(a, he, next, v, i, j, size, max_size, TYPE_Hash, TYPE_BlessedObject); \
        write_cwb(", '");                               \
        write_cwb(HvNAME(SvSTASH(v)));                  \
        write_cwb("')");                                \
    } while (0)

static char *FastSerializer_serializePerlObject(FastSerializer *fs, SV *v_)
{
    int callstack_idx = 0;
    static void *jmp_table[17] = {
        &&L(TYPE_Null), &&L(TYPE_Bind),
        &&L(TYPE_Int), &&L(TYPE_Double),
        &&L(TYPE_String), &&L(TYPE_PtrInt),
        &&L(TYPE_PtrDouble), &&L(TYPE_Object),
        &&L(TYPE_Regex), &&L(TYPE_Glob),
        &&L(TYPE_PVLV), &&L(TYPE_Array),
        &&L(TYPE_Hash), &&L(TYPE_Code),
        &&L(TYPE_FM), &&L(TYPE_IO),
        &&L(TOP),
    };
    DISPATCH_INIT();
    DISPATCH_TOP();
    DBG_PL("TOP");
    SV *v = (SvROK(v_)) ? DEREF(v_) : v_;
    if (SvOBJECT(v)) {
        DBG_PL("BLESS");
        FastSerializer_serializeBlessedObject(v);
        FAST_RETURN();
    } else {
        DISPATCH_TYPE(SvTYPE(v));
        CASE(TYPE_Int) {
            DBG_PL("INT");
            FastSerializer_serializeIntObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_PtrInt) {
            DBG_PL("PTRINT");
            FastSerializer_serializeIntPtrObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_Double) {
            DBG_PL("DOUBLE");
            FastSerializer_serializeDoubleObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_PtrDouble) {
            DBG_PL("PTRDOUBLE");
            FastSerializer_serializeDoublePtrObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_String) {
            DBG_PL("STRING");
            FastSerializer_serializeStringObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_Array) {
            DBG_PL("ARRAY");
            FastSerializer_serializeArrayObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_Hash) {
            DBG_PL("HASH");
            FastSerializer_serializeHashObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_Code) {
            DBG_PL("CODE");
            FastSerializer_serializeCodeObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_Glob) {
            DBG_PL("GLOB");
            FastSerializer_serializeGlobObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_PVLV) {
            DBG_PL("PVLV");
            FastSerializer_serializeLVObject(v);
            FAST_RETURN();
        }
        CASE(TYPE_Null) {
            DBG_PL("NULL");
            write_cwb("undef");
            FAST_RETURN();
        }
        CASE(TYPE_Bind) {
            DBG_PL("BIND");
            write_cwb("undef");
            FAST_RETURN();
        }
        CASE(TYPE_Object) {
            DBG_PL("OBJECT");
            write_cwb("undef");
            FAST_RETURN();
        }
        CASE(TYPE_Regex) {
            DBG_PL("REGEX");
            write_cwb("undef");
            FAST_RETURN();
        }
        CASE(TYPE_FM) {
            DBG_PL("FM");
            write_cwb("undef");
            FAST_RETURN();
        }
        CASE(TYPE_IO) {
            DBG_PL("IO");
            write_cwb("undef");
            FAST_RETURN();
        }
    }
    DISPATCH_END();
    DBG_PL("END");
    return cwb;
}

FastSerializer *new_FastSerializer(void)
{
    callstack = new_VirtualCallStack();
    callstack_top = callstack;
    FastSerializer *fs = safe_malloc(sizeof(FastSerializer));
    fs->serialize = FastSerializer_serializePerlObject;
    return fs;
}

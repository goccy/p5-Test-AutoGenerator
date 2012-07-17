#include "auto_test.h"


//========================<<< GLOBAL VARIABLE >>>=================================//
static jmp_buf jbuf;
static TestCodeGenerator *tcg = NULL;
static char *cwb;
static int cwb_idx = 0;
static char *use_list[] = {
    "use strict", "use warnings", "use FindBin::libs qw(base=lib)",
    "use FindBin::libs qw(base=inc)", "use Test::More \"no_plan\"", "use Test::MockObject",
    NULL
};
static int serialize_stack = 0;
static int memory_leaks = 0;

//============================<<< UTIL API >>>====================================//
static bool match(const char *from, const char *to)
{
    bool ret = false;
    size_t from_size = strlen(from) + 1;
    size_t to_size = strlen(to) + 1;
    if (from_size == to_size && !strncmp(from, to, to_size)) {
        ret = true;
    }
    return ret;
}

static bool find(const char *targ, char c) {
    bool ret = false;
    size_t size = strlen(targ);
    int i = 0;
    for (i = 0; i < size; i++) {
        if (targ[i] == c) {
            ret = true;
            break;
        }
    }
    return ret;
}

static void *safe_malloc(size_t size)
{
    void *ret = malloc(size);
    if (!ret) {
        fprintf(stderr, "ERROR!!:cannot allocate memory\n");
        exit(EXIT_FAILURE);
    }
    memset(ret, 0, size);
    memory_leaks += size;
    return ret;
}

static void safe_free(void *ptr, size_t size)
{
    if (ptr) {
        free(ptr);
        memory_leaks -= size;
        ptr = NULL;
    }
}

static void write_space(FILE *fp, int space_num, bool comment_out_flag)
{
    int i = 0;
    if (comment_out_flag) fprintf(fp, "#"); 
    for (i = 0; i < space_num; i++) {
        fprintf(fp, " ");
    }
}

static inline void write_cwb(char *buf)
{
    size_t buf_size = strlen(buf);
    strncpy(cwb + cwb_idx, buf, buf_size);
    cwb_idx += buf_size;
    if (cwb_idx > MAX_CWB_SIZE) {
        //fprintf(stderr, "ERROR: cwb_idx = [%d] > %d\n", cwb_idx, MAX_CWB_SIZE);
        serialize_stack = 0;
        memset(cwb, 0, MAX_CWB_SIZE);
        cwb_idx = 0;
        longjmp(jbuf, 1);
    }
}

static char *serializeObject(SV *v);
static void serializeHE(HE *he)
{
    char* key = he->hent_hek->hek_key;
    size_t len = strlen(key) + 1;
    char buf[len + 2];
    memset(buf, 0, len + 2);
    snprintf(buf, len + 2, "\"%s\"", key);
    write_cwb(buf);
    write_cwb(" => ");
    SV *val = he->he_valu.hent_val;
    serializeObject(val);
}

static void serializeHash(SV *v)
{
    XPVHV* xhv = (XPVHV*)SvANY(v);
    size_t key_n = xhv->xhv_keys;
    if (key_n > 0) {
        size_t max_size = xhv->xhv_max;
        HE *entries[key_n];
        int i = 0;
        int j = 0;
        for (i = 0; i <= max_size; i++) {
            HE *he = v->sv_u.svu_hash[i];
            if (he) {
                entries[j] = he;
                j++;
                HE *next = he->hent_next;
                while (next) {
                    entries[j] = next;
                    next = next->hent_next;
                    j++;
                }
            }
        }
        assert(j == key_n);
        for (i = 0; i < key_n; i++) {
            serializeHE(entries[i]);
            if (i + 1 != key_n) write_cwb(", ");//delim
        }
    }
}

static char buf[32] = {0};
static char *serializeObject(SV *v_)
{
    serialize_stack++;
    if (serialize_stack > MAX_MACHINE_STACK_SIZE) {
        serialize_stack = 0;
        memset(cwb, 0, cwb_idx);
        cwb_idx = 0;
        longjmp(jbuf, 1);
    }
    bool is_reference = false;
    SV *v;
    if (SvROK(v_)) {
        v = v_->sv_u.svu_rv;
        is_reference = true;
    } else {
        v = v_;
    }
    if (SvOBJECT(v)) {
        if (SvTYPE(v) != TYPE_Hash) {
            //fprintf(stderr, "TYPE = [%d]\n", SvTYPE(v));
            write_cwb("undef");
            goto BREAK;
        }
        write_cwb("bless (");
        (is_reference) ? write_cwb("{") :  write_cwb("(");
        serializeHash(v);
        (is_reference) ? write_cwb("}") :  write_cwb(")");
        write_cwb(", '");
        write_cwb(HvNAME(SvSTASH(v)));
        write_cwb("')");
    } else {
        if (SvROK(v)) {
            //fprintf(stderr, "STILL REFERENCE\n");
        }
        switch (SvTYPE(v)) {
        case TYPE_Int: {
            int ivalue = SvIVX(v);
            snprintf(buf, 32, "%d", ivalue);
            write_cwb(buf);
            memset(buf, 0, 32);
            break;
        }
        case TYPE_PtrInt: {
            char *ptr = v->sv_u.svu_pv;
            if (ptr) {
                snprintf(buf, 32, "%d", atoi(ptr));
            } else {
                snprintf(buf, 32, "0");
            }
            write_cwb(buf);
            memset(buf, 0, 32);
            break;
        }
        case TYPE_Double: {
            double dvalue = SvNVX(v);
            snprintf(buf, 32, "%f", dvalue);
            write_cwb(buf);
            memset(buf, 0, 32);
            break;
        }
        case TYPE_PtrDouble: {
            char *ptr = v->sv_u.svu_pv;
            if (ptr) {
                if (find(ptr, '.')) {
                    snprintf(buf, 32, "%f", atof(ptr));
                } else if (match(ptr, "")) {
                    snprintf(buf, 32, "\"\"");
                } else {
                    snprintf(buf, 32, "%d", atoi(ptr));
                }
            } else {
                snprintf(buf, 32, "''");
            }
            write_cwb(buf);
            memset(buf, 0, 32);
            break;
        }
        case TYPE_String: {
            char *svalue = SvPVX(v);
            if (svalue) {
                size_t len = strlen(svalue) + 1;
                size_t size = len;
                char sout[size];
                memset(sout, 0, size);
                char *ptr_in  = svalue;
                char *ptr_out = sout;
                iconv_t ic = iconv_open("EUC-JP", LOCALE);
                iconv(ic, &ptr_in, &len, &ptr_out, &len);
                iconv_close(ic);
                char buf[size + 2];
                memset(buf, 0, size + 2);
                snprintf(buf, size + 2, "\"%s\"", sout);
                write_cwb(buf);
            } else {
                write_cwb("''");
            }
            break;
        }
        case TYPE_Array: {
            int size = av_len((AV *)v);
            int i = 0;
            SV **a = v->sv_u.svu_array;
            if (a) {
                (is_reference) ? write_cwb("[") :  write_cwb("(");
                for (i = 0; i <= size; i++) {
                    if (a[i]) serializeObject(a[i]);
                    if (i != size) write_cwb(", ");//delim
                }
            } else {
                write_cwb("undef");
            }
            if (a) {
                (is_reference) ? write_cwb("]") :  write_cwb(")");
            }
            break;
        }
        case TYPE_Hash: {
            (is_reference) ? write_cwb("{") :  write_cwb("(");
            serializeHash(v);
            (is_reference) ? write_cwb("}") :  write_cwb(")");
            break;
        }
        case TYPE_Object: {
            //fprintf(stderr, "OBJECT\n");
            write_cwb("undef");
            break;
        }
        case TYPE_Code: {
            HV *stash_ = CvSTASH((CV *)v);
            if (!stash_) break;
            char *stash_name = HvNAME(stash_);
            char *func_name = GvNAME(CvGV((CV *)v));
            size_t stash_size = strlen(stash_name);
            size_t func_size = strlen(func_name);
            if (stash_size == 4 && !strncmp(stash_name, "main", 4)) {
                char buf[func_size + 8];
                sprintf(buf, "\\&%s", func_name);
                write_cwb(buf);
            } else {
                char buf[stash_size + func_size + 8];
                sprintf(buf, "\\&%s::%s", stash_name, func_name);
                write_cwb(buf);
            }
            break;
        }
        case SVt_PVLV: {
            XPVLV *xlv = (XPVLV *)v->sv_any;
            if (xlv->xlv_type == 'T') {
                //SV *targ = xlv->xlv_targ;
                //SV *lv = *(SV **)((HE*)xlv->xlv_targ)->hent_hek->hek_key;
                //serializeObject(lv);
            }/* else if (LvTYPE(sv) != 't') {
            }*/
            write_cwb("undef");
            break;
        }
        default:
            write_cwb("undef");
            break;
        }
    }
BREAK:;
    serialize_stack--;
    return cwb;
}



//========================= CallFlow Class API ===================================//

static void CallFlow_setReturnValue(CallFlow *cf, char *ret_value)
{
    size_t size = strlen(ret_value) + 1;
    char *str = safe_malloc(size);
    memcpy(str, ret_value, size);
    cf->ret = str;
}

static void CallFlow_free(CallFlow *cf)
{
    while (cf) {
        safe_free((char *)cf->from_stash, strlen(cf->from_stash) + 1);
        safe_free((char *)cf->from, strlen(cf->from) + 1);
        safe_free((char *)cf->to_stash, strlen(cf->to_stash) + 1);
        safe_free((char *)cf->to, strlen(cf->to) + 1);
        if (cf->ret) {
            safe_free((char *)cf->ret, strlen(cf->ret) + 1);
        }
        CallFlow *cur_cf = cf;
        cf = cf->next;
        safe_free(cur_cf, sizeof(CallFlow));
    }
}

static CallFlow *new_CallFlow(char *from_stash, char *from_subname,
                              char *to_stash, char *to_subname)
{
    CallFlow *cf = safe_malloc(sizeof(CallFlow));
    size_t from_stash_size = (from_stash) ? strlen(from_stash) + 1 : 0;
    size_t from_subname_size = (from_subname) ? strlen(from_subname) + 1 : 0;
    size_t to_stash_size = (to_stash) ? strlen(to_stash) + 1 : 0;
    size_t to_subname_size = (to_subname) ? strlen(to_subname) + 1 : 0;
    cf->from_stash = (const char *)safe_malloc(from_stash_size);
    memcpy((char *)cf->from_stash, from_stash, from_stash_size);
    cf->from = (const char *)safe_malloc(from_subname_size);
    memcpy((char *)cf->from, from_subname, from_subname_size);
    cf->to_stash = (const char *)safe_malloc(to_stash_size);
    memcpy((char *)cf->to_stash, to_stash, to_stash_size);
    cf->to = (const char *)safe_malloc(to_subname_size);
    memcpy((char *)cf->to, to_subname, to_subname_size);
    cf->setReturnValue = CallFlow_setReturnValue;
    cf->free = CallFlow_free;
    return cf;
}

//========================= MethodList Class API =================================//
static Method *mtd_lists[MAX_METHOD_NUM];
static int mtd_idx = 0;
static Method *MethodList_getMatchedMethod(Method **mtd_list, const char *mtd_name)
{
    Method *ret = NULL;
    size_t mtd_name_size = strlen(mtd_name) + 1;
    int i = 0;
    for (i = 0; i < mtd_idx; i++) {
        const char *cmp_name = mtd_list[i]->name;
        size_t cmp_name_size = strlen(cmp_name) + 1;
        if (mtd_name_size == cmp_name_size &&
            !strncmp(mtd_name, cmp_name, mtd_name_size)) {
            ret = mtd_list[i];
            break;
        }
    }
    return ret;
}

static void MethodList_addMethod(Method **mtd_list, Method *mtd)
{
    mtd_list[mtd_idx] = mtd;
    mtd_idx++;
    if (mtd_idx > MAX_METHOD_NUM) {
        fprintf(stderr, "ERROR!!: mtd num > %d\n", MAX_METHOD_NUM);
    }
}

//========================= Method Class API =================================//
static void Method_addCallFlow(Method *mtd, CallFlow *cf)
{
    if (!mtd->cfs) {
        mtd->cfs = cf;
    } else {
        CallFlow *cfs = mtd->cfs;
        for (; cfs->next; cfs = cfs->next) {}
        cfs->next = cf;
    }
}

static void Method_setArgs(Method *mtd, char *args)
{
    mtd->args = args;
}

static bool Method_existsCallFlow(Method *mtd, CallFlow *cf)
{
    bool ret = false;
    CallFlow *cfs = mtd->cfs;
    for (; cfs; cfs = cfs->next) {
        if (match(cfs->from_stash, cf->from_stash) &&
            match(cfs->from, cf->from) &&
            match(cfs->to_stash, cf->to_stash) &&
            match(cfs->to, cf->to)) {
            ret = true;
            break;
        }
    }
    return ret;
}

static void Method_free(Method *mtd)
{
    while (mtd) {
        safe_free((char *)mtd->name, strlen(mtd->name) + 1);
        if (mtd->args) safe_free((char *)mtd->args, strlen(mtd->args) + 1);
        if (mtd->cfs) {
            mtd->cfs->free(mtd->cfs);
        }
        Method *cur_mtd = mtd;
        mtd = mtd->next;
        safe_free(cur_mtd, sizeof(Method));
    }
}

static Method *new_Method(const char *name, const char *stash, const char *subname)
{
    Method *mtd = safe_malloc(sizeof(Method));
    mtd->name = name;
    mtd->stash = stash;
    mtd->subname = subname;
    mtd->ret = NULL;
    mtd->addCallFlow = Method_addCallFlow;
    mtd->existsCallFlow = Method_existsCallFlow;
    mtd->setArgs = Method_setArgs;
    mtd->free = Method_free;
    return mtd;
}

//========================= Package Class API =================================//
static void Package_addMethod(Package *pkg, Method *mtd)
{
    if (!mtd) {
        fprintf(stderr, "ERROR!!: Method is NULL\n");
        exit(EXIT_FAILURE);
    }
    if (!pkg->mtds) {
        pkg->mtds = mtd;
    } else {
        Method *mtds = pkg->mtds;
        for (; mtds->next; mtds = mtds->next) {}
        mtds->next = mtd;
    }
}

static bool Package_existsLibrary(Package *pkg, const char *path)
{
    bool ret = false;
    int i = 0;
    for (; i < pkg->lib_num; i++) {
        if (match(pkg->lib_paths[i], path)) {
            ret = true;
            break;
        }
    }
    return ret;
}

static void Package_addLibraryPath(Package *pkg, const char *path)
{
    pkg->lib_paths = (const char **)realloc(pkg->lib_paths, sizeof(char *) * (pkg->lib_num + 1));
    pkg->lib_paths[pkg->lib_num] = path;
    pkg->lib_num++;
}

static void Package_free(Package *pkg)
{
    while (pkg) {
        if (pkg->mtds) {
            pkg->mtds->free(pkg->mtds);
        }
        safe_free(pkg->lib_paths, sizeof(char *) * pkg->lib_num);
        Package *cur_pkg = pkg;
        pkg = pkg->next;
        safe_free(cur_pkg, sizeof(Package));
    }
}

static Package *new_Package(const char *pkg_name)
{
    Package *pkg = safe_malloc(sizeof(Package));
    pkg->name = pkg_name;
    pkg->addMethod = Package_addMethod;
    pkg->existsLibrary = Package_existsLibrary;
    pkg->addLibraryPath = Package_addLibraryPath;
    pkg->free = Package_free;
    return pkg;
}

//========================= Library Class API =================================//
//static Library *new_Library(char *path__)
//{
//    char *path_ = safe_malloc(strlen(path__) + 1);
//    strcpy(path_, path__);
//    char *path = safe_malloc(strlen(path_) + 1);
//    strcpy(path, path_);
//    char *tk = strtok(path_, "::");
//    char *name = NULL;
//    while (tk != NULL) {
//        tk = strtok(NULL, "::");
//        if (tk != NULL) name = tk;
//    }
//    Library *lib = safe_malloc(sizeof(Library));
//    lib->path = path;
//    lib->name = (name) ? name : path;
//    return lib;
//}

//========================= TestCodeGenerator Class API =================================//
static Package *TestCodeGenerator_getMatchedPackage(TestCodeGenerator *tcg, const char *pkg_name)
{
    Package *ret = NULL;
    Package *pkg_search_ptr = tcg->pkgs;
    size_t pkg_name_size = strlen(pkg_name) + 1;
    for (; pkg_search_ptr; pkg_search_ptr = pkg_search_ptr->next) {
        const char *cmp_name = pkg_search_ptr->name;
        size_t cmp_name_size = strlen(cmp_name) + 1;
        if (pkg_name_size == cmp_name_size &&
            !strncmp(pkg_name, cmp_name, pkg_name_size)) {
            ret = pkg_search_ptr;
            break;
        }
    }
    return ret;
}

static void TestCodeGenerator_addPackage(TestCodeGenerator *tcg, Package *pkg)
{
    if (!tcg->pkgs) {
        tcg->pkgs = pkg;
    } else {
        Package *pkgs = tcg->pkgs;
        for (; pkgs->next; pkgs = pkgs->next) {}
        pkgs->next = pkg;
    }
}

static const char *TestCodeGenerator_getLibraryPath(TestCodeGenerator *tcg, const char *libname)
{
    const char *ret = NULL;
    int i = 0;
    for (; i < tcg->lib_num; i++) {
        Library *lib = tcg->libs[i];
        if (match(lib->name, libname)) {
            ret = lib->path;
            break;
        }
    }
    return ret;
}

static void TestCodeGenerator_gen(TestCodeGenerator *tcg)
{
    char filename[MAX_FILE_NAME_SIZE] = {0};
    Package *pkgs = tcg->pkgs;
    CHANGE_COLOR(GREEN);
    fprintf(stderr, "AutoTest gen : START\n");
    CHANGE_COLOR(WHITE);
    for (; pkgs; pkgs = pkgs->next) {
        if (match(pkgs->name, "main")) continue;
        snprintf(filename, MAX_FILE_NAME_SIZE, "/tmp/%s.t", pkgs->name);
        FILE *fp;
        if ((fp = fopen(filename, "w")) == NULL) {
            fprintf(stderr, "ERROR!!: file open error[%s], (%s)\n", filename, strerror(errno));
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "AutoTest gen : [%s]\n", filename);
        int i = 0;
        for (i = 0; use_list[i] != NULL; i++) {
            fprintf(fp, "%s;\n", use_list[i]);
        }
        fprintf(fp, "\n");
        fprintf(fp, "use_ok('%s');\n", pkgs->name);
        i = 1;
        Method *mtds = pkgs->mtds;
        for (; mtds; mtds = mtds->next) {
            //fprintf(stderr, "mtds->name = [%s]\n", mtds->name);
            if (mtds->subname && match(mtds->subname, "main")) {
                i++; continue;
            }
            fprintf(fp, "sub test_%03d_%s {\n", i, mtds->subname);
            bool comment_out_flag = false;
            CallFlow *cfs = mtds->cfs;
            for (; cfs; cfs = cfs->next) {
                comment_out_flag = false;
                if (match(cfs->to_stash, mtds->stash)) continue;
                if (!cfs->ret || cfs->is_xs) comment_out_flag = true;
                write_space(fp, 4, comment_out_flag);
                fprintf(fp, "Test::MockObject->fake_module(\"%s\",\n", cfs->to_stash);
                write_space(fp, 8, comment_out_flag);
                fprintf(fp, "%s => sub {\n", cfs->to);
                write_space(fp, 12, comment_out_flag);
                if (cfs->is_xs) {
                    fprintf(fp, "%s\n", XS_ERROR_TEXT);
                } else if (!cfs->ret) {
                    fprintf(fp, "%s\n", TRACE_ERROR_TEXT);
                } else {
                    fprintf(fp, "%s;\n", cfs->ret);
                }
                write_space(fp, 8, comment_out_flag);
                fprintf(fp, "});\n");
            }
            comment_out_flag = false;
            if (mtds->args_error) comment_out_flag = true;
            if (mtds->stash && match(mtds->stash, "main")) {
                write_space(fp, 4, comment_out_flag);
                if (mtds->ret_type == TYPE_List) {
                    fprintf(fp, "my @ret = %s(", mtds->subname);
                } else if (!mtds->ret) {
                    write_space(fp, 4, comment_out_flag);
                    fprintf(fp, "%s(", mtds->subname);
                } else {
                    fprintf(fp, "my $ret = %s(", mtds->subname);
                }
            } else {
                write_space(fp, 4, comment_out_flag);
                if (mtds->ret_type == TYPE_List) {
                    fprintf(fp, "my @ret = %s::%s(", mtds->stash, mtds->subname);
                } else if (!mtds->ret) {
                    fprintf(fp, "%s::%s(", mtds->stash, mtds->subname);
                } else {
                    fprintf(fp, "my $ret = %s::%s(", mtds->stash, mtds->subname);
                }
            }
            if (mtds->args) {
                fprintf(fp, "%s", mtds->args);
            }
            if (mtds->args_error) {
                fprintf(fp, "); %s\n", TRACE_ERROR_TEXT);
            } else {
                fprintf(fp, ");\n");
            }
            if (mtds->ret) {
                switch (mtds->ret_type) {
                case TYPE_Int: case TYPE_Double:
                    write_space(fp, 4, comment_out_flag);
                    fprintf(fp, "ok($ret == %s, \"%s\");\n", mtds->ret, mtds->name);
                    break;
                case TYPE_PtrInt: case TYPE_PtrDouble:
                    write_space(fp, 4, comment_out_flag);
                    if (find(mtds->ret, '\"')) {
                        fprintf(fp, "ok($ret eq %s, \"%s\");\n", mtds->ret, mtds->name);
                    } else {
                        fprintf(fp, "ok($ret == %s, \"%s\");\n", mtds->ret, mtds->name);
                    }
                    break;
                case TYPE_String:
                    write_space(fp, 4, comment_out_flag);
                    fprintf(fp, "is($ret, %s, \"%s\");\n", mtds->ret, mtds->name);
                    break;
                case TYPE_Hash: case TYPE_Array:
                case TYPE_Code: case TYPE_Object:
                    write_space(fp, 4, comment_out_flag);
                    fprintf(fp, "is_deeply($ret, %s, \"%s\");\n", mtds->ret, mtds->name);
                    break;
                case TYPE_List:
                    write_space(fp, 4, comment_out_flag);
                    ((char *)mtds->ret)[0] = '[';
                    ((char *)mtds->ret)[strlen(mtds->ret) - 1] = ']';
                    fprintf(fp, "is_deeply(\\@ret, %s, \"%s\");\n", mtds->ret, mtds->name);
                    break;
                default:
                    write_space(fp, 4, comment_out_flag);
                    fprintf(fp, "ok($ret == %s, \"%s\");\n", mtds->ret, mtds->name);
                    break;
                }
            }
            fprintf(fp, "}\n");
            fprintf(fp, "\n");
            i++;
        }
        fprintf(fp, "\n");
        mtds = pkgs->mtds;
        i = 1;
        for (; mtds; mtds = mtds->next) {
            fprintf(fp, "test_%03d_%s;\n", i, mtds->subname);
            i++;
        }
        //fprintf(fp, "run_tests();\n");
        //fprintf(fp, "done_testing();\n");
        fclose(fp);
    }
}

static bool TestCodeGenerator_existsLibrary(TestCodeGenerator *tcg, const char *name)
{
    bool ret = false;
    int i = 0;
    for (; i < tcg->lib_num; i++) {
        if (match(tcg->libs[i]->name, name)) {
            ret = true;
            break;
        }
    }
    return ret;
}

static void TestCodeGenerator_free(TestCodeGenerator *tcg)
{
    if (tcg->pkgs) {
        tcg->pkgs->free(tcg->pkgs);
    }
    safe_free(tcg, sizeof(TestCodeGenerator));
}

TestCodeGenerator *new_TestCodeGenerator(void)
{
    TestCodeGenerator *tcg = safe_malloc(sizeof(TestCodeGenerator));
    tcg->getMatchedPackage = TestCodeGenerator_getMatchedPackage;
    tcg->addPackage = TestCodeGenerator_addPackage;
    tcg->getLibraryPath = TestCodeGenerator_getLibraryPath;
    tcg->existsLibrary = TestCodeGenerator_existsLibrary;
    tcg->gen = TestCodeGenerator_gen;
    tcg->free = TestCodeGenerator_free;
    return tcg;
}

//=====================================================================//

static OP *(*pp_return)(pTHX) = NULL;
static OP *(*pp_leavesub)(pTHX) = NULL;
static OP *(*pp_leavesublv)(pTHX) = NULL;
static OP *(*pp_goto)(pTHX) = NULL;
static OP *(*pp_entersub)(pTHX) = NULL;

//======================= FROM NYTProf ==============================//
static CV *resolve_sub_to_cv(pTHX_ SV *sv, GV **subname_gv_ptr)
{
    GV *dummy_gv;
    HV *stash;
    CV *cv;
    if (!subname_gv_ptr) {
        subname_gv_ptr = &dummy_gv;
    } else {
        *subname_gv_ptr = Nullgv;
    }
    switch (SvTYPE(sv)) {
    default:
        if (!SvROK(sv)) {
            char *sym;
            if (sv == &PL_sv_yes) {           /* unfound import, ignore */
                return NULL;
            }
            if (SvGMAGICAL(sv)) {
                mg_get(sv);
                if (SvROK(sv)) goto got_rv;
                sym = SvPOKp(sv) ? SvPVX(sv) : Nullch;
            } else {
                sym = SvPVX(sv);
            }
            if (!sym) return NULL;
            if (PL_op->op_private & HINT_STRICT_REFS) return NULL;
            cv = get_cv(sym, TRUE);
            break;
        }
    got_rv:;
        {
            SV **sp = &sv;                    /* Used in tryAMAGICunDEREF macro. */
            tryAMAGICunDEREF(to_cv);
        }
        cv = (CV*)SvRV(sv);
        if (SvTYPE(cv) == SVt_PVCV)
            break;
        /* FALL THROUGH */
    case SVt_PVHV:
    case SVt_PVAV:
        return NULL;
    case SVt_PVCV:
        cv = (CV*)sv;
        break;
    case SVt_PVGV:
        if (!(isGV_with_GP(sv) && (cv = GvCVu((GV*)sv))))
            cv = sv_2cv(sv, &stash, subname_gv_ptr, FALSE);
        if (!cv)                              /* would autoload in this situation */
            return NULL;
        break;
    }
    if (cv && !*subname_gv_ptr && CvGV(cv) && isGV_with_GP(CvGV(cv))) {
        *subname_gv_ptr = CvGV(cv);
    }
    return cv;
}

static CV* current_cv(pTHX_ I32 ix, PERL_SI *si)
{
    PERL_CONTEXT *cx;
    if (!si)
        si = PL_curstackinfo;
    if (ix < 0) {
        if (si->si_type != PERLSI_MAIN)
            return current_cv(aTHX_ si->si_prev->si_cxix, si->si_prev);
        return Nullcv;
    }
    cx = &si->si_cxstack[ix];
    if (CxTYPE(cx) == CXt_SUB || CxTYPE(cx) == CXt_FORMAT)
        return cx->blk_sub.cv;
    else if (CxTYPE(cx) == CXt_EVAL && !CxTRYBLOCK(cx))
        return current_cv(aTHX_ ix - 1, si);
    else if (ix == 0 && si->si_type == PERLSI_MAIN)
        return PL_main_cv;
    else if (ix > 0)
        return current_cv(aTHX_ ix - 1, si);

    if (si->si_type != PERLSI_MAIN) {
        return current_cv(aTHX_ si->si_prev->si_cxix, si->si_prev);
    }
    return Nullcv;
}

//================================================================================//
static CallFlow *cf_stack[MAX_CALLSTACK_SIZE] = {0};
static bool xs_stack[MAX_CALLSTACK_SIZE] = {0};
static char *get_serialized_argument(pTHX, int cxix, char *caller_name, char *callee_name)
{
    const bool hasargs = (PL_op->op_flags & OPf_STACKED) != 0;
    if (hasargs) {
        int i = 0;
        AV *argarray = my_perl->Icurstackinfo->si_cxstack[cxix].cx_u.cx_blk.blk_u.blku_sub.argarray;
        if (argarray && SvTYPE(argarray) == TYPE_Array) {
            int argc = argarray->sv_any->xav_fill;//av_len((AV *)argarray);
            SV **a = argarray->sv_u.svu_array;
            if (setjmp(jbuf) == 0) {
                if (a) {
                    for (i = 0; i <= argc; i++) {
                        serializeObject(a[i]);
                        if (i != argc) {
                            write_cwb(", ");//delim
                        }
                    }
                }
            } else {
                //CHANGE_COLOR(RED);
                //fprintf(stderr, "AutoTest Exception! [TOO LARGE BUFFER SIZE]: ");
                //CHANGE_COLOR(WHITE);
                //fprintf(stderr, "%s => %s (args)\n", caller_name, callee_name);
                return NULL;
            }
        }
    }
    size_t size = strlen(cwb) + 1;
    char *args = safe_malloc(size);
    memcpy(args, cwb, size);
    return args;
}

static void record_callflow(pTHX_ SV *sub_sv, OP *op)
{
    int cxix = my_perl->Icurstackinfo->si_cxix;
    int saved_errno = errno;
    OP *next_op = PL_op->op_next;
    OPCODE op_type = ((opcode) PL_op->op_type == OP_GOTO) ? (opcode) PL_op->op_type : OP_ENTERSUB;
    CV *callee_cv = NULL;
    char *callee_sub_name = NULL;
    char *caller_sub_name = NULL;
    if (op_type != OP_GOTO) {
        callee_cv = NULL;
    } else {
        //SvREFCNT_inc(sub_sv);
        callee_cv = (CV*)SvRV(sub_sv);
        SETERRNO(saved_errno, 0);
        //SvREFCNT_dec(sub_sv);
    }
    char *caller_stash_name = NULL;
    char *callee_stash_name = NULL;
    bool is_xs = false;
    if (op_type == OP_GOTO) {
        is_xs = (CvISXSUB(callee_cv)) ? true : false;
    } else {
        if (op != next_op) {
            callee_cv = cxstack[cxstack_ix].blk_sub.cv;
            is_xs = false;
        } else {
            GV *gv = NULL;
            callee_cv = resolve_sub_to_cv(aTHX_ sub_sv, &gv);
            if (!callee_cv && gv) {
                callee_stash_name = HvNAME(GvSTASH(gv));
                callee_sub_name = GvNAME(CvGV(callee_cv));
            }
            is_xs = true;
        }
    }
    xs_stack[cxix] = is_xs;
    if (callee_cv && CvGV(callee_cv)) {
        GV *gv = CvGV(callee_cv);
        if (SvTYPE(gv) == SVt_PVGV && GvSTASH(gv)) {
            callee_stash_name = HvNAME(GvSTASH(gv));
            callee_sub_name = GvNAME(CvGV(callee_cv));
        }
    }
    if (!callee_cv) {
        callee_stash_name = CopSTASHPV(PL_curcop);
    }
    CV *caller_cv = current_cv(aTHX_ cxstack_ix-1, NULL);
    if (caller_cv == PL_main_cv || !caller_cv) {
        caller_stash_name = "main";
        caller_sub_name = "main";
    } else {
        HV *stash_hv = NULL;
        GV *gv = CvGV(caller_cv);
        GV *egv = GvEGV(gv);
        if (!egv) gv = egv;
        if (gv && (stash_hv = GvSTASH(gv))) {
            caller_sub_name = GvNAME(CvGV(caller_cv));
            caller_stash_name = HvNAME(CvSTASH(caller_cv));
        }
    }
    if (!callee_sub_name) callee_sub_name = "main";
    SETERRNO(saved_errno, 0);
    if (match(caller_sub_name, "BEGIN") || match(callee_sub_name, "BEGIN") ||
        match(callee_sub_name, "export") || match(callee_sub_name, "import") ||
        match(caller_sub_name, "export") || match(caller_sub_name, "import") || is_xs) {
        return;
    }
    size_t callee_stash_size = strlen(callee_stash_name) + 1;
    size_t caller_stash_size = (caller_stash_name) ? strlen(caller_stash_name) + 1 : 0;
    size_t callee_subname_size = strlen(callee_sub_name) + 1;
    size_t caller_subname_size = (caller_sub_name) ? strlen(caller_sub_name) + 1 : 0;
    size_t callee_name_size = callee_stash_size + 2 + callee_subname_size;
    size_t caller_name_size = caller_stash_size + 2 + caller_subname_size;
    char *callee_name = (char *)safe_malloc(callee_name_size);
    char *caller_name = (char *)safe_malloc(caller_name_size);
    snprintf(callee_name, callee_name_size, "%s::%s", callee_stash_name, callee_sub_name);
    snprintf(caller_name, caller_name_size, "%s::%s", caller_stash_name, caller_sub_name);
    CallFlow *cf = new_CallFlow(caller_stash_name, caller_sub_name,
                                callee_stash_name, callee_sub_name);
    //fprintf(stderr, "stack = [%d]\n", cxix);
    //fprintf(stderr, "%s::%s => %s::%s\n", caller_name, callee_name);
    char *args = get_serialized_argument(aTHX, cxix, caller_name, callee_name);
    cf_stack[cxix] = cf;
    Package *from_pkg = NULL;
    Package *to_pkg = NULL;
    if (!tcg->pkgs) {
        from_pkg = new_Package(caller_stash_name);
        tcg->addPackage(tcg, from_pkg);
        if (callee_stash_name && !match(caller_stash_name, callee_stash_name)) {
            to_pkg = new_Package(callee_stash_name);
            tcg->addPackage(tcg, to_pkg);
        } else {
            to_pkg = from_pkg;
        }
    } else {
        if (caller_stash_name) {
            from_pkg = tcg->getMatchedPackage(tcg, caller_stash_name);
            if (!from_pkg) {
                from_pkg = new_Package(caller_stash_name);
                tcg->addPackage(tcg, from_pkg);
            }
        }
        if (callee_stash_name) {
            to_pkg = tcg->getMatchedPackage(tcg, callee_stash_name);
            if (!to_pkg) {
                to_pkg = new_Package(callee_stash_name);
                tcg->addPackage(tcg, to_pkg);
            }
        }
    }
    Method *from_mtd = MethodList_getMatchedMethod(mtd_lists, caller_name);
    Method *to_mtd = MethodList_getMatchedMethod(mtd_lists, callee_name);
    if (!from_mtd) {
        from_mtd = new_Method(caller_name, caller_stash_name, caller_sub_name);
        from_mtd->addCallFlow(from_mtd, cf);
        MethodList_addMethod(mtd_lists, from_mtd);
        if (from_pkg) from_pkg->addMethod(from_pkg, from_mtd);
    } else {
        if (!from_mtd->existsCallFlow(from_mtd, cf)) {
            from_mtd->addCallFlow(from_mtd, cf);
        }
        //safe_free(caller_name, caller_name_size);
    }
    if (!to_mtd) {
        to_mtd = new_Method(callee_name, callee_stash_name, callee_sub_name);
        if (args) {
            to_mtd->setArgs(to_mtd, args);
        } else {
            to_mtd->args_error = true;
        }
        if (!to_mtd->ret) {
            to_mtd->ret = cf->ret;
            to_mtd->ret_type = cf->ret_type;
        }
        MethodList_addMethod(mtd_lists, to_mtd);
        if (to_pkg) {
            to_pkg->addMethod(to_pkg, to_mtd);
        }
    } else {
        if (!to_mtd->ret) {
            to_mtd->ret = cf->ret;
            to_mtd->ret_type = cf->ret_type;
        }
        if (args) {
            if (!to_mtd->args) {
                to_mtd->setArgs(to_mtd, args);
            } else {
                safe_free(args, strlen(args) + 1);
            }
        } else {
            to_mtd->args_error = true;
        }
        //safe_free(callee_name, callee_name_size);
    }
}

static void record_return_value(pTHX)
{
    int cxix = my_perl->Icurstackinfo->si_cxix;
    SV **sp = my_perl->Istack_sp;
    //SV **mark = my_perl->Istack_base - *my_perl->Imarkstack_ptr-1;
    //I32 items = my_perl->Istack_sp - mark -1;
    int mark = *my_perl->Imarkstack_ptr;
    I32 items = my_perl->Istack_sp - my_perl->Istack_base;
    bool is_list = false;
    CallFlow *cf = cf_stack[cxix];
    if (!cf) return;
    bool is_xs = xs_stack[cxix];
    cf->is_xs = is_xs;
    if (cf && cf->ret) return;
    if (setjmp(jbuf) == 0) {
        if (cf->from &&
            (match(cf->from, "BEGIN") ||
             match(cf->from, "export") || match(cf->from, "import") ||
             match(cf->to, "export") || match(cf->to, "import"))) {
            return;
        } else if (!sp[0] || !SvOK(sp[0])) {
            return;
        } else if (items < 0) {
            serializeObject(sp[0]);
        } else {
            int i = 0;
            I32 gimme = my_perl->Icurstackinfo->si_cxstack[cxix].cx_u.cx_blk.blku_gimme;
            int oldsp = my_perl->Icurstackinfo->si_cxstack[cxix].cx_u.cx_blk.blku_oldsp;
            mark = oldsp;
            //const unsigned char type = my_perl->Isavestack->any_uv & SAVE_MASK;
            //if (type == SAVEt_STACK_CXPOS) {}
            if (gimme == G_ARRAY) {
                //if (SvTYPE(my_perl->Icurstackinfo->si_stack) == TYPE_Array) {
                //fprintf(stderr, "%s::%s => %s::%s\n", cf->from_stash, cf->from, cf->to_stash, cf->to);
                //fprintf(stderr, "hasrvalue, [%d]\n", items);
                if (items > 1 + mark) {
                    is_list = true;
                    write_cwb("(");
                }
                SV **base = my_perl->Istack_base;
                for (i = 1 + mark; i <= items; i++) {
                    if (base[i]) {
                        serializeObject(base[i]);
                    } else {
                        break;
                    }
                    if (i != items) {
                        write_cwb(", ");//delim
                    }
                }
                if (items > 1 + mark) {
                    write_cwb(")");
                }
            } else {
                serializeObject(sp[0]);
            }
        }
    } else {
        //CHANGE_COLOR(RED);
        //fprintf(stderr, "AutoTest Exception! [TOO LARGE BUFFER SIZE]: ");
        //CHANGE_COLOR(WHITE);
        //fprintf(stderr, "%s::%s => %s::%s (rvalue)\n",
          //      cf->from_stash, cf->from, cf->to_stash, cf->to);
        return;
    }
    cf->setReturnValue(cf, cwb);
    if (is_list) {
        cf->ret_type = TYPE_List;
    } else {
        cf->ret_type = (SvROK(sp[0])) ? SvTYPE(SvRV(sp[0])) : SvTYPE(sp[0]);
    }
    size_t size = strlen(cf->to_stash) + strlen(cf->to) + 4;
    char to_buf[size];
    snprintf(to_buf, size, "%s::%s", cf->to_stash, cf->to);
    Method *to_mtd = MethodList_getMatchedMethod(mtd_lists, to_buf);
    if (to_mtd && !to_mtd->ret) {
        to_mtd->ret = cf->ret;
        to_mtd->ret_type = cf->ret_type;
    }
    //fprintf(stderr, "RET = [%s]\n", cf->ret);
}

OP *hook_goto(pTHX)
{
    dSP;
    SV *sub_sv = *SP;
    OP *op = pp_goto(aTHX);
    record_callflow(aTHX_ sub_sv, op);
    memset(cwb, 0, cwb_idx);
    cwb_idx = 0;
    return op;
}

OP *hook_leavesub(pTHX)
{
    record_return_value(aTHX);
    memset(cwb, 0, cwb_idx);
    cwb_idx = 0;
    OP *op = pp_leavesub(aTHX);
    return op;
}

OP *hook_leavesublv(pTHX)
{
    record_return_value(aTHX);
    memset(cwb, 0, cwb_idx);
    cwb_idx = 0;
    OP *op = pp_leavesublv(aTHX);
    return op;
}

OP *hook_return(pTHX)
{
    record_return_value(aTHX);
    memset(cwb, 0, cwb_idx);
    cwb_idx = 0;
    OP *op = pp_return(aTHX);
    return op;
}

OP *hook_entersub(pTHX)
{
    dSP;
    SV *sub_sv = *SP;
    OP *op = pp_entersub(aTHX);
    record_callflow(aTHX_ sub_sv, op);
    memset(cwb, 0, cwb_idx);
    cwb_idx = 0;
    return op;
}


MODULE = AutoTest     PACKAGE = AutoTest
PROTOTYPES: ENABLE

void
import(klass, SV *flags = NULL)
CODE:
{
    pp_entersub = PL_ppaddr[OP_ENTERSUB];
    pp_leavesub = PL_ppaddr[OP_LEAVESUB];
	pp_leavesublv = PL_ppaddr[OP_LEAVESUBLV];
    pp_return = PL_ppaddr[OP_RETURN];
    pp_goto = PL_ppaddr[OP_GOTO];
    PL_ppaddr[OP_ENTERSUB] = hook_entersub;
    PL_ppaddr[OP_LEAVESUB] = hook_leavesub;
	PL_ppaddr[OP_LEAVESUBLV] = hook_leavesublv;
    PL_ppaddr[OP_RETURN] = hook_return;
    PL_ppaddr[OP_GOTO] = hook_goto;
    tcg = new_TestCodeGenerator();
    cwb = (char *)safe_malloc(MAX_CWB_SIZE);
}

void
END()
CODE:
{
    tcg->gen(tcg);
    PL_ppaddr[OP_ENTERSUB] = pp_entersub;
    PL_ppaddr[OP_LEAVESUB] = pp_leavesub;
	PL_ppaddr[OP_LEAVESUBLV] = pp_leavesublv;
    PL_ppaddr[OP_RETURN] = pp_return;
    PL_ppaddr[OP_GOTO] = pp_goto;
    CHANGE_COLOR(SYAN);
    fprintf(stderr, "AutoTest gen: exit normaly.\n");
    CHANGE_COLOR(WHITE);
    //tcg->free(tcg);
    //safe_free(cwb, MAX_CWB_SIZE);
    if (memory_leaks > 0) {
        fprintf(stderr, "memory_leaks = %d bytes\n", memory_leaks);
    }
}

void
dump_vmcode()
CODE:
{
    OP *pc = my_perl->Iop;
    fprintf(stderr, "========= DUMP VMCODE =======\n");
    for (; pc; pc = pc->op_next) {
        fprintf(stderr, "[%s]\n", OP_NAME(pc));
    }
    fprintf(stderr, "=============================\n");
}

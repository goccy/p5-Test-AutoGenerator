#include "auto_test.h"
static TestCodeGenerator *tcg = NULL;
static char cwb[MAX_CWB_SIZE] = {0};
static int cwb_idx = 0;
static Args *args_stack[MAX_CALLSTACK_SIZE];
static int args_stack_idx = 0;
static char *use_list[] = {
	"use strict", "use warnings", "use FindBin::libs qw(base=lib)",
	"use FindBin::libs qw(base=inc)", "use Test::More \"no_plan\"", "use Test::MockObject",
	NULL
};

static FILE *error_log = NULL;

static bool match(char *from, char *to)
{
	bool ret = false;
	size_t from_size = strlen(from) + 1;
	size_t to_size = strlen(to) + 1;
	if (from_size == to_size && !strncmp(from, to, to_size)) {
		ret = true;
	}
	return ret;
}

static void write_space(FILE *fp, int space_num)
{
	int i = 0;
	for (i = 0; i < space_num; i++) {
		fprintf(fp, " ");
	}
}

static void write_cwb(char *buf)
{
	size_t buf_size = strlen(buf);
	strncpy(cwb + cwb_idx, buf, buf_size);
	cwb_idx += buf_size;
	if (cwb_idx > MAX_CWB_SIZE) {
		fprintf(stderr, "ERROR: cwb_idx > %d\n", MAX_CWB_SIZE);
		fprintf(error_log, "ERROR: cwb_idx > %d\n", MAX_CWB_SIZE);
		exit(EXIT_FAILURE);
	}
}

#ifdef SvRV
#undef SvRV
#define SvRV(sv) ((sv)->sv_u.svu_rv)
#endif
#include <iconv.h>

static char *serializeObject(SV *v)
{
	char buf[32] = {0};
	bool is_reference = false;
	if (SvROK(v)) {
		v = SvRV(v);
		is_reference = true;
	}
	if (SvOBJECT(v)) {
        if (SvTYPE(v) != TYPE_Hash) {
            goto BREAK;
        }
		write_cwb("bless (");
		HE **he = v->sv_u.svu_hash;
		(is_reference) ? write_cwb("{") :  write_cwb("(");
		if (he) {
			int i = 0;
			for (i = 0; he[i] != NULL; i++) {
				SV*	key = hv_iterkeysv(he[i]);
				serializeObject(key);
				write_cwb(" => ");
				SV*	val = hv_iterval((HV *)v, he[i]);
				serializeObject(val);
				if (he[i + 1] != NULL) write_cwb(", ");//delim
			}
		}
		(is_reference) ? write_cwb("}") :  write_cwb(")");
		write_cwb(", '");
		write_cwb(HvNAME(SvSTASH(v)));
		write_cwb("')");
	} else {
		switch (SvTYPE(v)) {
		case TYPE_Int: case SVt_PVIV: {
			int ivalue = SvIVX(v);
			snprintf(buf, 32, "%d", ivalue);
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
		case TYPE_String: {
			char *svalue = SvPVX(v);
			fprintf(stderr, "svalue = [%s]\n", svalue);
            size_t len = strlen(svalue) + 1;
			size_t buf_size = len;
            char sout[len];
			char buf[buf_size + 2];
			fprintf(stderr, "len = [%d]\n", len);
            char *ptr_in  = svalue;
            char *ptr_out = sout;
            iconv_t ic = iconv_open("EUC-JP", "UTF-8");
            iconv(ic, &ptr_in, &len, &ptr_out, &len);
            iconv_close(ic);
            if (!svalue) {
                write_cwb("undef");
            } else {
                snprintf(buf, buf_size + 2, "'%s'", sout);
				fprintf(stderr, "buf = [%s]\n", buf);
                write_cwb(buf);
            }
			break;
		}
		case TYPE_Array: {
			(is_reference) ? write_cwb("[") :  write_cwb("(");
			int size = av_len((AV *)v);
			int i = 0;
			SV **a = v->sv_u.svu_array;
			for (i = 0; i <= size; i++) {
				serializeObject(a[i]);
				if (i != size) write_cwb(", ");//delim
			}
			(is_reference) ? write_cwb("]") :  write_cwb(")");
			break;
		}
		case TYPE_Hash: {
			(is_reference) ? write_cwb("{") :  write_cwb("(");
			HE *he = hv_iternext((HV *)v);
			while (he) {
				SV*	key = hv_iterkeysv(he);
				serializeObject(key);
				write_cwb(" => ");
				SV*	val = hv_iterval((HV *)v, he);
				serializeObject(val);
				he = hv_iternext((HV *)v);
				if (he) {
					write_cwb(", ");//delim
				}
			}
			(is_reference) ? write_cwb("}") :  write_cwb(")");
			break;
		}
		case TYPE_Object: {
			//fprintf(stderr, "ret = (blessed object,[%p])\n", v);
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
		default:
			write_cwb("undef");
			break;
		}
	}
BREAK:;
	return cwb;
}


static void CallFlow_setReturnValue(CallFlow *cf, char *ret_value)
{
	size_t size = strlen(ret_value) + 1;
	char *str = malloc(size);
	memcpy(str, ret_value, size);
	cf->ret = str;
}

static CallFlow *new_CallFlow(char *from_stash, char *from_subname,
							  char *to_stash, char *to_subname)
{
	CallFlow *cf = malloc(sizeof(CallFlow));
	memset(cf, 0, sizeof(CallFlow));
	size_t from_stash_size = (from_stash) ? strlen(from_stash) + 1 : 0;
	size_t from_subname_size = (from_subname) ? strlen(from_subname) + 1 : 0;
	size_t to_stash_size = (to_stash) ? strlen(to_stash) + 1 : 0;
	size_t to_subname_size = (to_subname) ? strlen(to_subname) + 1 : 0;
	cf->from_stash = (const char *)malloc(from_stash_size);
	memcpy((char *)cf->from_stash, from_stash, from_stash_size);
	cf->from = (const char *)malloc(from_subname_size);
	memcpy((char *)cf->from, from_subname, from_subname_size);
	cf->to_stash = (const char *)malloc(to_stash_size);
	memcpy((char *)cf->to_stash, to_stash, to_stash_size);
	cf->to = (const char *)malloc(to_subname_size);
	memcpy((char *)cf->to, to_subname, to_subname_size);
	cf->setReturnValue = CallFlow_setReturnValue;
	return cf;
}

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
        fprintf(error_log, "ERROR!!: mtd num > %d\n", MAX_METHOD_NUM);
	}
}

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
//	if (args->size > MAX_ARGS_NUM) {
//		fprintf(stderr, "ERROR!!: args num [%d] > %d\n", args->size, MAX_ARGS_NUM);
//		fprintf(error_log, "ERROR!!: args num [%d] > %d\n", args->size, MAX_ARGS_NUM);
//		exit(EXIT_FAILURE);
//	}
	mtd->args = malloc(sizeof(char *) * 1);//args->size);
	memset(mtd->args, 0, sizeof(char *) * 1);//args->size);
//	int i = (mtd->subname && match((char *)mtd->subname, "new")) ? 1 : 0;
//	for (; i < args->size; i++) {
//		mtd->args[i] = args->v[i];
//	}
    mtd->args[0] = args;
    mtd->args_size = 1;//args->size - 1;
}

static Method *new_Method(const char *name, const char *stash, const char *subname)
{
	Method *mtd = malloc(sizeof(Method));
	memset(mtd, 0, sizeof(Method));
	mtd->name = name;
	mtd->stash = stash;
	mtd->subname = subname;
	mtd->addCallFlow = Method_addCallFlow;
	mtd->setArgs = Method_setArgs;
	return mtd;
}

static void Package_addMethod(Package *pkg, Method *mtd)
{
	if (!mtd) {
		fprintf(stderr, "ERROR!!: Method is NULL\n");
        fprintf(error_log, "ERROR!!: Method is NULL\n");
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
        if (match((char *)pkg->lib_paths[i], (char *)path)) {
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

static Package *new_Package(const char *pkg_name)
{
	Package *pkg = malloc(sizeof(Package));
	memset(pkg, 0, sizeof(Package));
	pkg->name = pkg_name;
	pkg->addMethod = Package_addMethod;
    pkg->existsLibrary = Package_existsLibrary;
    pkg->addLibraryPath = Package_addLibraryPath;
	return pkg;
}

static Library *new_Library(char *path_)
{
    char *path = malloc(strlen(path_) + 1);
    strcpy(path, path_);
    char *tk = strtok(path_, "::");
    char *name = NULL;
    while (tk != NULL) {
        tk = strtok(NULL, "::");
        if (tk != NULL) name = tk;
    }
    Library *lib = malloc(sizeof(Library));
    memset(lib, 0, sizeof(Library));
    lib->path = path;
    lib->name = (name) ? name : path;
    return lib;
}

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
        if (match((char *)lib->name, (char *)libname)) {
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
	for (; pkgs; pkgs = pkgs->next) {
        if (match((char *)pkgs->name, "main")) continue;
		snprintf(filename, MAX_FILE_NAME_SIZE, "%s.t", pkgs->name);
		//fprintf(stderr, "FILENAME = [%s]\n", filename);
		FILE *fp;
		if ((fp = fopen(filename, "w")) == NULL) {
			fprintf(stderr, "ERROR!!: file open error[%s]\n", filename);
            fprintf(error_log, "ERROR!!: file open error[%s]\n", filename);
			exit(EXIT_FAILURE);
		}
		int i = 0;
		for (i = 0; use_list[i] != NULL; i++) {
			fprintf(fp, "%s;\n", use_list[i]);
		}
		fprintf(fp, "\n");
        {
            Package *pkg = pkgs;
            Method *mtds = pkg->mtds;
            for (; mtds; mtds = mtds->next) {
                Method *mtd = mtds;
                const char *path = (mtd->stash) ? tcg->getLibraryPath(tcg, mtd->stash) : NULL;
                if (path && !pkg->existsLibrary(pkg, path)) {
                    pkg->addLibraryPath(pkg, path);
                }
                CallFlow *cfs = mtd->cfs;
                for (; cfs; cfs = cfs->next) {
                    CallFlow *cf = cfs;
                    path = tcg->getLibraryPath(tcg, cf->from_stash);
                    if (path && !pkg->existsLibrary(pkg, path)) {
                        pkg->addLibraryPath(pkg, path);
                    }
                    path = tcg->getLibraryPath(tcg, cf->to_stash);
                    if (path && !pkg->existsLibrary(pkg, path)) {
                        pkg->addLibraryPath(pkg, path);
                    }
                }
            }
        }
        int j = 0;
        for (; j < pkgs->lib_num; j++) {
            fprintf(fp, "use_ok('%s');\n", pkgs->lib_paths[j]);
        }
		i = 1;
		Method *mtds = pkgs->mtds;
		for (; mtds; mtds = mtds->next) {
			//fprintf(stderr, "mtds->name = [%s]\n", mtds->name);
			if (mtds->subname && match((char *)mtds->subname, "main")) {
				i++; continue;
			}
			fprintf(fp, "sub test_%03d_%s {\n", i, mtds->subname);
			CallFlow *cfs = mtds->cfs;
			for (; cfs; cfs = cfs->next) {
				write_space(fp, 4);
				fprintf(fp, "Test::MockObject->fake_module('%s',\n", cfs->to_stash);
				write_space(fp, 8);
				fprintf(fp, "%s => sub {\n", cfs->to);
				write_space(fp, 12);
				fprintf(fp, "%s;\n", cfs->ret);
				write_space(fp, 8);
				fprintf(fp, "});\n");
			}
			if (mtds->stash && match((char *)mtds->stash, "main")) {
				write_space(fp, 4);
				if (mtds->ret_type == TYPE_List) {
					fprintf(fp, "my @ret = %s(", mtds->subname);
				} else {
					fprintf(fp, "my $ret = %s(", mtds->subname);
				}
			} else {
				write_space(fp, 4);
				if (mtds->ret_type == TYPE_List) {
					fprintf(fp, "my @ret = %s::%s(", mtds->stash, mtds->subname);
				} else {
				    fprintf(fp, "my $ret = %s::%s(", mtds->stash, mtds->subname);
				}
			}
			int j = 0;
			if (mtds->args) {
				for (j = 0; j < mtds->args_size; j++) {
                    if (!mtds->args[j]) continue;
					fprintf(fp, "%s", mtds->args[j]);
					//if (mtds->args[j + 1]) fprintf(fp, ", ");
				}
			}
			fprintf(fp, ");\n");
			switch (mtds->ret_type) {
			case TYPE_Int: case TYPE_Double:
				write_space(fp, 4);
				fprintf(fp, "ok($ret, %s);\n", mtds->ret);
				break;
			case TYPE_String:
				write_space(fp, 4);
				fprintf(fp, "is($ret, %s);\n", mtds->ret);
				break;
			case TYPE_Hash: case TYPE_Array:
			case TYPE_Code: case TYPE_Object:
				write_space(fp, 4);
				fprintf(fp, "is_deeply($ret, %s);\n", mtds->ret);
				break;
			case TYPE_List:
				write_space(fp, 4);
				((char *)mtds->ret)[0] = '[';
				((char *)mtds->ret)[strlen(mtds->ret) - 1] = ']';
				fprintf(fp, "is_deeply(\\@ret, %s);\n", mtds->ret);
				break;
			default:
				break;
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
        if (match((char *)tcg->libs[i]->name, (char *)name)) {
            ret = true;
            break;
        }
    }
    return ret;
}

TestCodeGenerator *new_TestCodeGenerator(void)
{
	TestCodeGenerator *tcg = malloc(sizeof(TestCodeGenerator));
	memset(tcg, 0, sizeof(TestCodeGenerator));
	tcg->getMatchedPackage = TestCodeGenerator_getMatchedPackage;
	tcg->addPackage = TestCodeGenerator_addPackage;
    tcg->getLibraryPath = TestCodeGenerator_getLibraryPath;
    tcg->existsLibrary = TestCodeGenerator_existsLibrary;
	tcg->gen = TestCodeGenerator_gen;
	return tcg;
}

static OP *(*enter_sub)(pTHX_ OP *op) = NULL;
static OP *(*invoke_enter_sub)(pTHX) = NULL;
static OP *(*invoke_leave_sub)(pTHX) = NULL;

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

#define OP_NEXT() my_perl->Iop->op_next
static int cf_stack_idx = 0;
static CallFlow *cf_stack[MAX_CALLSTACK_SIZE] = {0};
static OP *pp_subcall_profiler(pTHX_ SV *sub_sv, OP *op)
{
    int saved_errno = errno;
    COP *prev_cop = PL_curcop;
    OP *next_op = PL_op->op_next;
    OPCODE op_type = ((opcode) PL_op->op_type == OP_GOTO) ? (opcode) PL_op->op_type : OP_ENTERSUB;
    CV *callee_cv = NULL;
    char *callee_sub_name = NULL;
    char *caller_sub_name = NULL;
    I32 this_subr_entry_ix = 0;
    if (op_type != OP_GOTO) {
        callee_cv = NULL;
    } else {
        SvREFCNT_inc(sub_sv);
        callee_cv = (CV*)SvRV(sub_sv);
        SETERRNO(saved_errno, 0);
        SvREFCNT_dec(sub_sv);
    }
    char *caller_stash_name = NULL;
    char *callee_stash_name = NULL;
    const char *is_xs = NULL;
    if (op_type == OP_GOTO) {
        is_xs = (CvISXSUB(callee_cv)) ? "xsub" : NULL;
    } else {
        if (op != next_op) {
            callee_cv = cxstack[cxstack_ix].blk_sub.cv;
            is_xs = NULL;
            fprintf(stderr, "hoge\n");
        } else {
            GV *gv = NULL;
            callee_cv = resolve_sub_to_cv(aTHX_ sub_sv, &gv);
            if (!callee_cv && gv) {
                callee_stash_name = HvNAME(GvSTASH(gv));
                callee_sub_name = GvNAME(CvGV(callee_cv));
                fprintf(stderr, "callee_stash_name = [%s]\n", callee_stash_name);
                fprintf(stderr, "callee_sub_name = [%s]\n", callee_sub_name);
            }
            is_xs = "xsub";
            fprintf(stderr, "fuga\n");
        }
    }
    if (callee_cv && CvGV(callee_cv)) {
        GV *gv = CvGV(callee_cv);
        if (SvTYPE(gv) == SVt_PVGV && GvSTASH(gv)) {
            callee_stash_name = HvNAME(GvSTASH(gv));
            callee_sub_name = GvNAME(CvGV(callee_cv));
            fprintf(stderr, "callee_stash_name = [%s]\n", callee_stash_name);
            fprintf(stderr, "callee_sub_name = [%s]\n", callee_sub_name);
        }
    }
    const char *what = (is_xs) ? is_xs : "sub";
    if (!callee_cv) {
        callee_stash_name = CopSTASHPV(PL_curcop);
        fprintf(stderr, "callee_stash_name = [%s]\n", callee_stash_name);
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
            fprintf(stderr, "caller_stash_name = [%s]\n", HvNAME(CvSTASH(caller_cv)));
            fprintf(stderr, "caller_sub_name = [%s]\n", caller_sub_name);
        }
    }
    if (!callee_sub_name) callee_sub_name = "main";
    SETERRNO(saved_errno, 0);
    dSP;
    sp = my_perl->Istack_sp;
    SV **mark = my_perl->Istack_base - *my_perl->Imarkstack_ptr-1;
    I32 items = my_perl->Istack_sp - mark -1;
    const bool hasargs = (PL_op->op_flags & OPf_STACKED) != 0;
	const char *use_name = NULL;
	bool is_list = false;
	if (caller_sub_name && match((char *)caller_sub_name, "BEGIN")) {
        if (!args_stack[args_stack_idx]->v[0]) return op;
        use_name = args_stack[args_stack_idx]->v[0] + 1; //cut ['];
        if (!use_name) return op;
        ((char *)use_name)[strlen(use_name) - 1] = '\0';
        if (!tcg->existsLibrary(tcg, use_name)) {
            fprintf(stderr, "use_name = [%s]\n", use_name);
            fprintf(error_log, "use_name = [%s]\n", use_name);
            Library *lib = new_Library((char *)use_name);
            tcg->libs = (Library **)realloc(tcg->libs, sizeof(Library) * (tcg->lib_num + 1));
            tcg->libs[tcg->lib_num] = lib;
            tcg->lib_num++;
        }
        fprintf(stderr, "==============END===============\n");
        return op;
	} else if (callee_sub_name && (match(callee_sub_name, "BEGIN") ||
                                   match(callee_sub_name, "export") || match(callee_sub_name, "import") ||
                                   match(caller_sub_name, "export") || match(caller_sub_name, "import"))) {
        fprintf(stderr, "=========================\n");
        return op;
    } else if (hasargs && items < 0) {
		serializeObject(sp[0]);
	} else if (hasargs) {
		int i = 0;
		if (items > 1) {
			is_list = true;
			write_cwb("(");
		}
		for (i = 1 - items; 1 > i; i++) {
			serializeObject(sp[i]);//descending order
			if (i != 0) {
				write_cwb(", ");
			}
		}
		if (items > 1) write_cwb(")");
	}
    size_t size = strlen(cwb) + 1;
	char *args = malloc(size);
	memcpy(args, cwb, size);
	size_t callee_stash_size = strlen(callee_stash_name) + 1;
	size_t caller_stash_size = (caller_stash_name) ? strlen(caller_stash_name) + 1 : 0;
	size_t callee_subname_size = strlen(callee_sub_name) + 1;
	size_t caller_subname_size = (caller_sub_name) ? strlen(caller_sub_name) + 1 : 0;
	size_t callee_name_size = callee_stash_size + 2 + callee_subname_size;
	size_t caller_name_size = caller_stash_size + 2 + caller_subname_size;
	char *callee_name = (char *)malloc(callee_name_size);
	char *caller_name = (char *)malloc(caller_name_size);
	snprintf(callee_name, callee_name_size, "%s::%s", callee_stash_name, callee_sub_name);
	snprintf(caller_name, caller_name_size, "%s::%s", caller_stash_name, caller_sub_name);
	CallFlow *cf = new_CallFlow(caller_stash_name, caller_sub_name,
								callee_stash_name, callee_sub_name);
    fprintf(stderr, "cwb = [%s]\n", cwb);
    cf_stack[cf_stack_idx] = cf;
	//fprintf(stderr, "cwb = [%s]\n", cwb);
	memset(cwb, 0, MAX_CWB_SIZE);
	cwb_idx = 0;
	Package *from_pkg = NULL;
	Package *to_pkg = NULL;
	if (!tcg->pkgs) {
		//fprintf(stderr, "init pkg_lists\n");
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
                //fprintf(stderr, "pkg is not exists\n");
                from_pkg = new_Package(caller_stash_name);
                tcg->addPackage(tcg, from_pkg);
            }
        }
        if (callee_stash_name) {
            to_pkg = tcg->getMatchedPackage(tcg, callee_stash_name);
            if (!to_pkg) {
                //fprintf(stderr, "pkg is not exists\n");
                to_pkg = new_Package(callee_stash_name);
                tcg->addPackage(tcg, to_pkg);
            }
        }
	}
	Method *from_mtd = MethodList_getMatchedMethod(mtd_lists, caller_name);
	Method *to_mtd = MethodList_getMatchedMethod(mtd_lists, callee_name);
	if (!from_mtd) {
		//fprintf(stderr, "from_method is not exists\n");
        //fprintf(stderr, "called_stash_name = [%s]\n", called_stash_name);
		from_mtd = new_Method(caller_name, caller_stash_name, caller_sub_name);
		from_mtd->addCallFlow(from_mtd, cf);
		MethodList_addMethod(mtd_lists, from_mtd);
        if (from_pkg) from_pkg->addMethod(from_pkg, from_mtd);
	} else {
		//fprintf(stderr, "exists method\n");
		from_mtd->addCallFlow(from_mtd, cf);
	}
	if (!to_mtd) {
		//fprintf(stderr, "to_method is not exists\n");
        //fprintf(stderr, "caller_stash_name = [%s]\n", caller_stash_name);
		to_mtd = new_Method(callee_name, callee_stash_name, callee_sub_name);
		to_mtd->setArgs(to_mtd, args);//args_stack[args_stack_idx]);
		if (!to_mtd->ret) {
			to_mtd->ret = cf->ret;
			to_mtd->ret_type = cf->ret_type;
		}
		MethodList_addMethod(mtd_lists, to_mtd);
		if (to_pkg) to_pkg->addMethod(to_pkg, to_mtd);
	} else {
		//fprintf(stderr, "exists method\n");
		if (!to_mtd->ret) {
			to_mtd->ret = cf->ret;
			to_mtd->ret_type = cf->ret_type;
		}
		to_mtd->setArgs(to_mtd, args);//_stack[args_stack_idx]);
	}
    fprintf(stderr, "=========================\n");
    return my_perl->Iop->op_next;
}

static OP *record_return_value(pTHX)
{
    SV **sp = my_perl->Istack_sp;
    SV **mark = my_perl->Istack_base - *my_perl->Imarkstack_ptr-1;
    I32 items = my_perl->Istack_sp - mark -1;
	const char *use_name = NULL;
	bool is_list = false;
    fprintf(stderr, "cf_stack_idx = [%d]\n", cf_stack_idx);
    if (cf_stack_idx < 0) cf_stack_idx = 0;
    CallFlow *cf = cf_stack[cf_stack_idx];
    if (!cf || (cf && cf->ret)) {
        goto BREAK;
    }
	if (cf && cf->from && (match(cf->from, "BEGIN") ||
                           match(cf->from, "export") || match(cf->from, "import") ||
                           match(cf->to, "export") || match(cf->to, "import"))) {
        fprintf(stderr, "========ESCAPE=======\n");
        return my_perl->Iop->op_next;
    } else if (!sp[0] || !SvOK(sp[0])) {
		fprintf(stderr, "return void function\n");
        return my_perl->Iop->op_next;
	} else if (items < 0) {
		serializeObject(sp[0]);
	} else {
		int i = 0;
		if (items > 1) {
			is_list = true;
			write_cwb("(");
		}
		for (i = 1 - items; 1 > i; i++) {
            fprintf(stderr, "sp[i] = %p\n", sp[i]);
			serializeObject(sp[i]);//descending order
			if (i != 0) {
				write_cwb(", ");
			}
		}
		if (items > 1) write_cwb(")");
	}
	if (cf) {
        cf->setReturnValue(cf, cwb);
        if (is_list) {
            cf->ret_type = TYPE_List;
        } else {
            cf->ret_type = (SvROK(sp[0])) ? SvTYPE(SvRV(sp[0])) : SvTYPE(sp[0]);
        }
        size_t size = strlen(cf->from_stash) + strlen(cf->from) + 4;
        char from_buf[size];
        snprintf(from_buf, size, "%s::%s", cf->from_stash, cf->from);
        Method *from_mtd = MethodList_getMatchedMethod(mtd_lists, from_buf);
        size = strlen(cf->to_stash) + strlen(cf->to) + 4;
        char to_buf[size];
        snprintf(to_buf, size, "%s::%s", cf->to_stash, cf->to);
        Method *to_mtd = MethodList_getMatchedMethod(mtd_lists, to_buf);
        //fprintf(stderr, "from_mtd = [%p]\n", from_mtd);
        //fprintf(stderr, "to_mtd = [%p]\n", to_mtd);
        if (from_mtd && !from_mtd->ret) {
            from_mtd->ret = cf->ret;
            from_mtd->ret_type = cf->ret_type;
        }
        if (to_mtd && !to_mtd->ret) {
            to_mtd->ret = cf->ret;
            to_mtd->ret_type = cf->ret_type;
        }
    }
BREAK:;
	fprintf(stderr, "cwb = [%s]\n", cwb);
	memset(cwb, 0, MAX_CWB_SIZE);
	cwb_idx = 0;
    fprintf(stderr, "=========================\n");
    return my_perl->Iop->op_next;
}

OP *insert_analyze_inst(pTHX)
{
    OP *pc = my_perl->Iop;
	OP *next = pc->op_next;
	OP *func = (OP *)malloc(sizeof(OP));
	memcpy(func, pc, sizeof(OP));
	func->op_ppaddr = record_return_value;
	pc->op_next = func;
	func->op_next = next;
    dSP;
    SV *sub_sv = *SP;
    cf_stack_idx++;
    OP *op = PL_ppaddr[OP_ENTERSUB](aTHX);
    pp_subcall_profiler(aTHX_ sub_sv, op);
    return op;
}

OP *hook_entersub(pTHX_ OP *o)
{
	o->op_ppaddr = insert_analyze_inst;
	enter_sub(aTHX, o);
	return o;
}

OP *hook_ret(pTHX)
{
	cf_stack_idx--;
	return my_perl->Iop->op_next;
}

MODULE = AutoTest		PACKAGE = AutoTest
PROTOTYPES: ENABLE

void
import(klass, SV *flags = NULL)
CODE:
{
    error_log = fopen("/tmp/auto_test_error_log", "w");
    enter_sub = PL_check[OP_ENTERSUB];
	PL_check[OP_ENTERSUB] = hook_entersub;
	PL_ppaddr[OP_RETURN] = hook_ret;
    //invoke_enter_sub = PL_ppaddr[OP_ENTERSUB];
    //PL_ppaddr[OP_ENTERSUB] = pp_subcall_profiler;
    //PL_ppaddr[OP_ENTERSUB] = hook_invoke_entersub;
	tcg = new_TestCodeGenerator();
	int i, j;
	for (i = 0; i < MAX_CALLSTACK_SIZE; i++) {
		args_stack[i] = (Args *)malloc(sizeof(Args));
        memset(args_stack[i], 0, sizeof(Args));
        args_stack[i]->size = 0;
		for (j = 0; j < MAX_ARGS_NUM; j++) {
			args_stack[i]->v[j] = NULL;
		}
	}
}

void
END()
CODE:
{
	tcg->gen(tcg);
    fclose(error_log);
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

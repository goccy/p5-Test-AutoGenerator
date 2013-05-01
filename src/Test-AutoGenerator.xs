#include "auto_generator.hpp"

//========================<<< GLOBAL VARIABLE >>>=================================//
jmp_buf jbuf;
static TestCodeGenerator *tcg = NULL;

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
			if (sv == &PL_sv_yes) {/* unfound import, ignore */
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
			SV **sp = &sv; /* Used in tryAMAGICunDEREF macro. */
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
		if (!cv)/* would autoload in this situation */
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
	if (!si) si = PL_curstackinfo;
	if (ix < 0) {
		if (si->si_type != PERLSI_MAIN) {
			return current_cv(aTHX_ si->si_prev->si_cxix, si->si_prev);
		}
		return Nullcv;
	}
	cx = &si->si_cxstack[ix];
	if (CxTYPE(cx) == CXt_SUB || CxTYPE(cx) == CXt_FORMAT) {
		return cx->blk_sub.cv;
	} else if (CxTYPE(cx) == CXt_EVAL && !CxTRYBLOCK(cx)) {
		return current_cv(aTHX_ ix - 1, si);
	} else if (ix == 0 && si->si_type == PERLSI_MAIN) {
		return PL_main_cv;
	} else if (ix > 0) {
		return current_cv(aTHX_ ix - 1, si);
	}
	if (si->si_type != PERLSI_MAIN) {
		return current_cv(aTHX_ si->si_prev->si_cxix, si->si_prev);
	}
	return Nullcv;
}

//================================================================================//
static CallFlow *cf_stack[MAX_CALLSTACK_SIZE] = {0};
static bool xs_stack[MAX_CALLSTACK_SIZE] = {0};
static char *get_serialized_argument(pTHX_ int cxix, const char *caller_name, const char *callee_name)
{
	const bool hasargs = (PL_op->op_flags & OPf_STACKED) != 0;
	if (!hasargs) return NULL;
	int i = 0;
	AV *argarray = PL_curstackinfo->si_cxstack[cxix].cx_u.cx_blk.blk_u.blku_sub.argarray;
	if (!argarray || (PerlType)SvTYPE(argarray) != TYPE_Array) return NULL;
	int argc = argarray->sv_any->xav_fill;//av_len((AV *)argarray);
	SV **a = argarray->sv_u.svu_array;
	if (!a) return NULL;
	if (setjmp(jbuf) == 0) {
		for (i = 0; i <= argc; i++) {
			tcg->fs->serialize(a[i]);
			if (i != argc) write_cwb(", ");//delim
		}
	} else {
		CHANGE_COLOR(RED);
		fprintf(stderr, "Test::AutoGenerator Exception! [TOO LARGE BUFFER SIZE]: ");
		CHANGE_COLOR(WHITE);
		fprintf(stderr, "%s => %s (args)\n", caller_name, callee_name);
		return NULL;
	}
	char *args = (char *)strclone(cwb);
	//fprintf(stderr, "ARGS = [%s]\n", args);
	return args;
}

static void set_callee_information(pTHX_ char **callee_stash_name, char **callee_sub_name, SV *sub_sv, OP *op)
{
	int cxix = PL_curstackinfo->si_cxix;
	int saved_errno = errno;
	OP *next_op = PL_op->op_next;
	OPCODE op_type = ((opcode) PL_op->op_type == OP_GOTO) ? (opcode) PL_op->op_type : OP_ENTERSUB;
	CV *callee_cv = NULL;
	if (op_type == OP_GOTO) {
		callee_cv = (CV*)SvRV(sub_sv);
		SETERRNO(saved_errno, 0);
	}
	bool is_xs = false;
	if (op_type == OP_GOTO) {
		is_xs = (CvISXSUB(callee_cv)) ? true : false;
	} else if (op != next_op) {
		callee_cv = cxstack[cxstack_ix].blk_sub.cv;
		is_xs = false;
	} else {
		GV *gv = NULL;
		callee_cv = resolve_sub_to_cv(aTHX_ sub_sv, &gv);
		if (callee_cv && gv) {
			*callee_stash_name = HvNAME(GvSTASH(gv));
			*callee_sub_name = GvNAME(CvGV(callee_cv));
		}
		is_xs = true;
	}
	xs_stack[cxix] = is_xs;
	if (callee_cv && CvGV(callee_cv)) {
		GV *gv = CvGV(callee_cv);
		if (SvTYPE(gv) == SVt_PVGV && GvSTASH(gv)) {
			*callee_stash_name = HvNAME(GvSTASH(gv));
			*callee_sub_name = GvNAME(CvGV(callee_cv));
		}
	}
	if (!callee_cv) *callee_stash_name = CopSTASHPV(PL_curcop);
	if (!*callee_sub_name) *callee_sub_name = (char *)"main";
}

static void set_caller_information(pTHX_ char **caller_stash_name, char **caller_sub_name)
{
	CV *caller_cv = current_cv(aTHX_ cxstack_ix-1, NULL);
	if (caller_cv == PL_main_cv || !caller_cv) {
		*caller_stash_name = (char *)"main";
		*caller_sub_name = (char *)"main";
	} else {
		HV *stash_hv = NULL;
		GV *gv = CvGV(caller_cv);
		GV *egv = GvEGV(gv);
		if (!egv) gv = egv;
		if (gv && (stash_hv = GvSTASH(gv))) {
			*caller_sub_name = GvNAME(CvGV(caller_cv));
			*caller_stash_name = HvNAME(CvSTASH(caller_cv));
		}
	}
}

static void record_callflow(pTHX_ SV *sub_sv, OP *op)
{
	char *callee_stash_name = NULL;
	char *callee_sub_name = NULL;
	char *caller_stash_name = NULL;
	char *caller_sub_name = NULL;
	set_callee_information(aTHX_ &callee_stash_name, &callee_sub_name, sub_sv, op);
	set_caller_information(aTHX_ &caller_stash_name, &caller_sub_name);
	assert(callee_stash_name && "callee_stash_name is NULL");
	assert(callee_sub_name && "callee_sub_name is NULL");
	assert(caller_stash_name && "caller_stash_name is NULL");
	assert(caller_sub_name && "caller_sub_name is NULL");
	int cxix = PL_curstackinfo->si_cxix;
	bool is_xs = xs_stack[cxix];
	if (match(caller_sub_name, "BEGIN") || match(callee_sub_name, "BEGIN") ||
		match(callee_sub_name, "export") || match(callee_sub_name, "import") ||
		match(caller_sub_name, "export") || match(caller_sub_name, "import") || is_xs) {
		return;
	}
	const char *callee_name = safe_sprintf("%s::%s", callee_stash_name, callee_sub_name);
	const char *caller_name = safe_sprintf("%s::%s", caller_stash_name, caller_sub_name);
	CallFlow *cf = new CallFlow(caller_stash_name, caller_sub_name, callee_stash_name, callee_sub_name);
	//fprintf(stderr, "stack = [%d]\n", cxix);
	//fprintf(stderr, "%s => %s\n", caller_name, callee_name);
	char *args = get_serialized_argument(aTHX_ cxix, caller_name, callee_name);
	cf_stack[cxix] = cf;
	Package *from_pkg = (tcg->existsPackage(caller_stash_name))
		? tcg->getPackage(caller_stash_name)
		: tcg->addPackage(new Package(caller_stash_name));
	Package *to_pkg = (tcg->existsPackage(callee_stash_name))
		? tcg->getPackage(callee_stash_name)
		: tcg->addPackage(new Package(callee_stash_name));
	//Method *from_mtd = new Method(caller_name, caller_stash_name, caller_sub_name);
	Method *from_mtd = from_pkg->getMethod(caller_sub_name);
	if (from_mtd) from_mtd->addCallFlow(cf);
	//from_pkg->addMethod(from_mtd);
	Method *to_mtd = new Method(callee_name, callee_stash_name, callee_sub_name);
	to_mtd->args = args;
	to_pkg->addMethod(to_mtd);
}

static void record_return_value(pTHX)
{
	int cxix = PL_curstackinfo->si_cxix;
	SV **sp = PL_stack_sp;
	int mark = *PL_markstack_ptr;
	I32 items = PL_stack_sp - PL_stack_base;
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
			tcg->fs->serialize(sp[0]);
		} else {
			int i = 0;
			I32 gimme = PL_curstackinfo->si_cxstack[cxix].cx_u.cx_blk.blku_gimme;
			int oldsp = PL_curstackinfo->si_cxstack[cxix].cx_u.cx_blk.blku_oldsp;
			mark = oldsp;
			if (gimme == G_ARRAY) {
				//fprintf(stderr, "rvalue : %s::%s => %s::%s\n", cf->from_stash, cf->from, cf->to_stash, cf->to);
				if (items > 1 + mark) {
					is_list = true;
					write_cwb("(");
				}
				SV **base = PL_stack_base;
				for (i = 1 + mark; i <= items; i++) {
					if (base[i]) {
						tcg->fs->serialize(base[i]);
					} else {
						break;
					}
					if (i != items) write_cwb(", ");
				}
				if (items > 1 + mark) {
					write_cwb(")");
				}
			} else {
				tcg->fs->serialize(sp[0]);
			}
		}
	} else {
		CHANGE_COLOR(RED);
		fprintf(stderr, "Test::AutoGenerator Exception! [TOO LARGE BUFFER SIZE]: ");
		CHANGE_COLOR(WHITE);
		fprintf(stderr, "%s::%s => %s::%s (rvalue)\n",
				cf->from_stash, cf->from, cf->to_stash, cf->to);
		return;
	}
	cf->setReturnValue(cwb, (is_list)
					   ? TYPE_List
					   : (SvROK(sp[0]))
					   ? (PerlType)SvTYPE(SvRV(sp[0]))
					   : (PerlType)SvTYPE(sp[0]));
	Package *pkg = tcg->getPackage(cf->to_stash);
	assert(pkg && "not found package");
	Method *mtd = pkg->getMethod(cf->to);
	assert(mtd && "not found method");
	mtd->setReturnValue(cf->ret, cf->ret_type);
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


MODULE = Test::AutoGenerator     PACKAGE = Test::AutoGenerator
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
	tcg = new TestCodeGenerator();
	cwb = (char *)safe_malloc(MAX_CWB_SIZE);
}

void
END()
CODE:
{
	tcg->gen();
	PL_ppaddr[OP_ENTERSUB] = pp_entersub;
	PL_ppaddr[OP_LEAVESUB] = pp_leavesub;
	PL_ppaddr[OP_LEAVESUBLV] = pp_leavesublv;
	PL_ppaddr[OP_RETURN] = pp_return;
	PL_ppaddr[OP_GOTO] = pp_goto;
	CHANGE_COLOR(SYAN);
	fprintf(stderr, "Test::AutoGenerator::gen exit normaly\n");
	CHANGE_COLOR(WHITE);
	//tcg->free(tcg);
	//safe_free(cwb, MAX_CWB_SIZE);
	if (leaks() > 0) {
		//fprintf(stderr, "memory_leaks = %d bytes\n", leaks());
	}
}

void
dump_vmcode()
CODE:
{
	OP *pc = PL_op;
	fprintf(stderr, "========= DUMP VMCODE =======\n");
	for (; pc; pc = pc->op_next) {
		fprintf(stderr, "[%s]\n", OP_NAME(pc));
	}
	fprintf(stderr, "=============================\n");
}

void
set_generated_library_name(self, libs_)
	SV *self
	AV *libs_
CODE:
{
	if (!tcg) return;
	size_t libs_size = av_len(libs_);
	SV **libs = libs_->sv_u.svu_array;
	if (!libs) return;
	for (size_t i = 0; i <= libs_size; i++) {
		const char *libname = SvPVX(libs[i]);
		tcg->addGeneratedLibraryName(libname);
	}
}

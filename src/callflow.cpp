#include <auto_generator.hpp>

CallFlow::CallFlow(const char *from_stash, const char *from_subname, const char *to_stash, const char *to_subname)
{
	this->from_stash = strclone(from_stash);
	this->from = strclone(from_subname);
	this->to_stash = strclone(to_stash);
	this->to = strclone(to_subname);
	this->ret = NULL;
	flow_raw_format = safe_sprintf("%s::%s->%s::%s", from_stash, from_subname, to_stash, to_subname);
}

void CallFlow::setReturnValue(char *ret_value, PerlType type)
{
	ret = strclone(ret_value);
	ret_type = type;
}

void CallFlow::dump(void)
{
	fprintf(stdout, "%s\n", flow_raw_format);
	fprintf(stdout, "rvalue = [%s]\n", ret);
}

CallFlow::~CallFlow(void)
{
}

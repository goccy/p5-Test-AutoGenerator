#include <auto_generator.hpp>
using namespace std;

Method::Method(const char *name, const char *stash, const char *subname)
{
	this->name = strclone(name);
	this->stash = strclone(stash);
	this->subname = strclone(subname);
	this->cfs = new CallFlowMap();
	this->ret = NULL;
}

void Method::setReturnValue(const char *ret_value, PerlType type)
{
	ret = strclone(ret_value);
	ret_type = type;
}

void Method::dump(void)
{
	fprintf(stdout, "method : %s\n", name);
	cfs->dump();
}

void Method::addCallFlow(CallFlow *cf)
{
	CallFlowList *list = (existsCallFlow(cf)) ?
		cfs->get(cf->flow_raw_format) : new CallFlowList();
	list->add(cf);
	cfs->add(CallFlowMap::value_type(cf->flow_raw_format, list));
}

bool Method::existsCallFlow(CallFlow *cf)
{
	return cfs->exists(cf->flow_raw_format);
}

Method::~Method(void)
{
}

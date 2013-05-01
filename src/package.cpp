#include <auto_generator.hpp>

Package::Package(const char *pkg_name)
{
	name = strclone(pkg_name);
	mtds = new MethodMap();
	libs = new LibraryMap();
}

Method *Package::getMethod(const char *mtd_name)
{
	if (!mtds->size()) return NULL;
	MethodList *list = mtds->get(mtd_name);
	MethodList::reverse_iterator it = list->rbegin();
	Method *mtd = NULL;
	while (it != list->rend()) {
		mtd = *it;
		if (!mtd->ret) return mtd;
		it++;
	}
	return mtd;
}

void Package::addMethod(Method *mtd)
{
	assert(mtd && "ERROR!!: Method is NULL\n");
	MethodList *list = (mtds->exists(mtd->subname)) ?
		mtds->get(mtd->subname) : new MethodList();
	list->add(mtd);
	mtds->add(MethodMap::value_type(mtd->subname, list));
}

bool Package::existsLibrary(const char *path)
{
	return libs->exists(path);
}

void Package::addLibraryPath(const char *path)
{
	libs->add(LibraryMap::value_type(path, path));
}

void Package::dump(void)
{
	fprintf(stdout, "package : %s\n", name);
	fprintf(stdout, "methods : \n");
	mtds->dump();
}

Package::~Package(void)
{
}


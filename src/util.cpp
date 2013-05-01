#include <auto_generator.hpp>

bool match(const char *from, const char *to)
{
	bool ret = false;
	size_t from_size = strlen(from) + 1;
	size_t to_size = strlen(to) + 1;
	if (from_size == to_size && !strncmp(from, to, to_size)) {
		ret = true;
	}
	return ret;
}

bool find(const char *targ, char c)
{
	bool ret = false;
	size_t size = strlen(targ);
	for (size_t i = 0; i < size; i++) {
		if (targ[i] == c) {
			ret = true;
			break;
		}
	}
	return ret;
}

static int memory_leaks = 0;
const char *strclone(const char *base)
{
	if (!base) return NULL;
	size_t size = strlen(base) + 1;
	char *ret = (char *)safe_malloc(size);
	memcpy(ret, base, size);
	return (const char *)ret;
}

const char *safe_sprintf(const char *format, ...)
{
	va_list argp;
	va_start(argp, format);
	for (char *ch = (char *)format; *ch != EOL; ch++) {
		if (*ch == '%' && *(ch+1) == 's') {
			char *s = va_arg(argp, char *);
			write_cwb(s);
			ch++;
		} else {
			char buf[2] = {0};
			buf[0] = *ch;
			write_cwb(buf);
		}
	}
	va_end(argp);
	const char *ret = strclone(cwb);
	memset(cwb, 0, cwb_idx);
	cwb_idx = 0;
	return ret;
}

void *safe_malloc(size_t size)
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

void safe_free(void *ptr, size_t size)
{
	if (ptr) {
		free(ptr);
		memory_leaks -= size;
		ptr = NULL;
	}
}

int leaks(void)
{
	return memory_leaks;
}

void write_space(FILE *fp, int space_num, bool comment_out_flag)
{
	int i = 0;
	if (comment_out_flag) fprintf(fp, "#");
	for (i = 0; i < space_num; i++) {
		fprintf(fp, " ");
	}
}

char *cwb;
int cwb_idx = 0;
void write_cwb(const char *buf)
{
	size_t buf_size = strlen(buf);
	strncpy(cwb + cwb_idx, buf, buf_size);
	cwb_idx += buf_size;
	if (cwb_idx > MAX_CWB_SIZE) {
		fprintf(stderr, "ERROR: cwb_idx = [%d] > %d\n", cwb_idx, MAX_CWB_SIZE);
		memset(cwb, 0, MAX_CWB_SIZE);
		cwb_idx = 0;
		longjmp(jbuf, 1);
	}
}

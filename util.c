#include "auto_test.h"

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

bool find(const char *targ, char c) {
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

static int memory_leaks = 0;
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
inline void write_cwb(char *buf)
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

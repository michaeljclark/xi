/*
 * test_sem.cc
 */

#undef NDEBUG
#include <cassert>
#include <cinttypes>
#include <threads.h>

#include "xi_nub.h"
#include "xi_common.h"

void test_lock()
{
    char sem_file[MAXPATHLEN];
    xi_nub_ctx* ctx = xi_nub_ctx_get_root_context();
    const char* profile_path = xi_nub_ctx_get_profile_path(ctx);
    snprintf(sem_file, sizeof(sem_file), "%s%s", profile_path,
        PATH_SEPARATOR "semaphore");

    bool is_leader = false;
    auto f = _open_file(sem_file, file_create_new, file_append);
    if (f.has_error()) {
        f = _open_file(sem_file, file_open_existing, file_append);
    } else {
        is_leader = true;
    }
    uint32_t pid = (uint32_t)_get_processs_id();
    _write(&f, &pid, sizeof(pid));
    xi_nub_result off = _get_file_offset(&f);
    uint32_t ticket = (uint32_t)off.bytes >> 2;
    _close(&f);

    printf("%s: ticket=%u, is_leader=%u, pid=%u, file=%s\n",
    	__func__, ticket, is_leader, pid, sem_file);
}

static uint64_t t1, t2, t3, t4;
static xi_nub_platform_semaphore test_sem1;

int test_sem_cb(void*)
{
	t2 = _clock_time_ns();
	_semaphore_wait(&test_sem1, 1000);
	printf("%s: woke\n", __func__);
	t3 = _clock_time_ns();
	return 5;
}

static void msleep(int millis)
{
    struct timespec tv = { millis / 1000, (millis % 1000) * 1000000 };
    thrd_sleep(&tv, NULL);
}

void test_sem()
{
	thrd_t t;
	int res;
	static const char *sem_name = "test_sem1";

	test_sem1 = _semaphore_create(sem_name);
	if (test_sem1.has_error() && test_sem1.error_code() == xi_nub_eexist) {
		test_sem1 = _semaphore_open(sem_name);
	}
	assert(!test_sem1.has_error());

	t1 = _clock_time_ns();
	thrd_create(&t, &test_sem_cb, NULL);
	msleep(300);
	_semaphore_signal(&test_sem1);
	thrd_join(t, &res);
	t4 = _clock_time_ns();

	_semaphore_close(&test_sem1);
	_semaphore_unlink(sem_name);

	printf("t1=%" PRId64 "ns t2=%" PRId64 "ns\n", (t3-t2), (t4-t1));

	const uint64_t MS = 1000000;
	assert(res == 5);
	assert((t3-t2) < 350 * MS);
	assert((t3-t2) > 250 * MS);
	assert((t4-t1) < 350 * MS);
	assert((t4-t1) > 250 * MS);
}

int main()
{
	test_lock();
	test_sem();
}

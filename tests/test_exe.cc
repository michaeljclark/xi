/*
 * test_sem.cc
 */

#undef NDEBUG
#include <cstdio>
#include <cassert>
#include <cinttypes>

#include "xi_common.h"

bool _debug_enabled;

void test_executable_path()
{
	std::string path = _executable_path();
	printf("%s\n", path.c_str());
}

int main()
{
	test_executable_path();
}

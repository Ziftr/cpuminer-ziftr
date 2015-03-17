#ifndef __COMPAT_H__
#define __COMPAT_H__

#ifdef WIN32

#include <windows.h>

//when compiling using mingw this method is already declared in unistd.h
//having it declared again of course breaks the compile, so we probably don't need to re-declare this anymore
/**
static inline void sleep(int secs)
{
	Sleep(secs * 1000);
}
**/

enum {
	PRIO_PROCESS		= 0,
};

static inline int setpriority(int which, int who, int prio)
{
	return -!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

#endif /* WIN32 */

#endif /* __COMPAT_H__ */

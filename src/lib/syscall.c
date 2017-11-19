/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <common/log.h>

#include "torsocks.h"

/* syscall(2) */
TSOCKS_LIBC_DECL(syscall, LIBC_SYSCALL_RET_TYPE, LIBC_SYSCALL_SIG)

/*
 * Torsocks call for syscall(2)
 */
LIBC_SYSCALL_RET_TYPE tsocks_syscall(long int number, va_list args)
{
	LIBC_SYSCALL_RET_TYPE ret;
        unsigned long a0, a1, a2, a3, a4, a5;
        a0 = va_arg(args, __typeof__(a0));
        a1 = va_arg(args, __typeof__(a1));
        a2 = va_arg(args, __typeof__(a2));
        a3 = va_arg(args, __typeof__(a3));
        a4 = va_arg(args, __typeof__(a4));
        a5 = va_arg(args, __typeof__(a5));
	switch (number) {
	case TSOCKS_NR_SOCKET:
          //hijacking accept4(2)
          ret = tsocks_socket(a0, a1, a2);
          break;
	case TSOCKS_NR_CONNECT:
          //hijacking accept4(2)
          ret = tsocks_connect(a0, (const struct sockaddr *)a1, a2);
          break;
	case TSOCKS_NR_CLOSE:
          //hijacking accept4(2)
          ret = tsocks_close(a0);
          break;
	case TSOCKS_NR_ACCEPT:
          //hijacking accept4(2)
          ret = tsocks_accept(a0, (struct sockaddr *)a1, (socklen_t *)a2);
          break;
	case TSOCKS_NR_GETPEERNAME:
          //hijacking accept4(2)
          ret = tsocks_getpeername(a0, (struct sockaddr *)a1, (socklen_t *)a2);
          break;
	case TSOCKS_NR_LISTEN:
          //hijacking accept4(2)
          ret = tsocks_listen(a0, a1);
          break;
	case TSOCKS_NR_RECVMSG:
          //hijacking accept4(2)
          ret = tsocks_recvmsg(a0, (struct msghdr *)a1, a2);
          break;
#if defined(__linux__)
	case TSOCKS_NR_ACCEPT4:
          //hijacking accept4(2)
          ret = tsocks_accept4(a0, (struct sockaddr *)a1, (socklen_t *)a2, a3);
          break;
#endif
	default:
          tsocks_libc_syscall(number, a0, a1, a2, a3, a4, a5);
	}

	return ret;
}

/*
 * Libc hijacked symbol syscall(2).
 */
LIBC_SYSCALL_DECL
{
	LIBC_SYSCALL_RET_TYPE ret;
	va_list args;

	if (!tsocks_libc_syscall) {
		tsocks_initialize();
		tsocks_libc_syscall= tsocks_find_libc_symbol(
				LIBC_SYSCALL_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	va_start(args, number);
	ret = tsocks_syscall(number, args);
	va_end(args);

	return ret;
}

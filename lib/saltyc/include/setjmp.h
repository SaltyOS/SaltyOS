/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SETJMP_H__
#define __SETJMP_H__

/* jmp_buf: 8 x 64-bit registers (rbx, rbp, r12-r15, rsp, rip) */
typedef unsigned long jmp_buf[8];
typedef unsigned long sigjmp_buf[10];

extern int  setjmp(jmp_buf env);
extern void longjmp(jmp_buf env, int val);
extern int  _setjmp(jmp_buf env);
extern void _longjmp(jmp_buf env, int val);
extern int  sigsetjmp(sigjmp_buf env, int savesigs);
extern void siglongjmp(sigjmp_buf env, int val);

#endif /* __SETJMP_H__ */

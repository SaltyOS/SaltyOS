/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MATH_H__
#define __MATH_H__

/* Classification constants (match __fpclassify return values) */
#define FP_NAN       0
#define FP_INFINITE  1
#define FP_ZERO      2
#define FP_SUBNORMAL 3
#define FP_NORMAL    4

/* IEEE 754 special values */
#define HUGE_VAL     __builtin_huge_val()
#define HUGE_VALF    __builtin_huge_valf()
#define HUGE_VALL    __builtin_huge_vall()
#define INFINITY     __builtin_inff()
#define NAN          __builtin_nanf("")

/* Mathematical constants */
#define M_E        2.7182818284590452354
#define M_LOG2E    1.4426950408889634074
#define M_LOG10E   0.43429448190325182765
#define M_LN2      0.69314718055994530942
#define M_LN10     2.30258509299404568402
#define M_PI       3.14159265358979323846
#define M_PI_2     1.57079632679489661923
#define M_PI_4     0.78539816339744830962
#define M_1_PI     0.31830988618379067154
#define M_2_PI     0.63661977236758134308
#define M_2_SQRTPI 1.12837916709551257390
#define M_SQRT2    1.41421356237309504880
#define M_SQRT1_2  0.70710678118654752440

/* Classification macros */
extern int __fpclassify(double x);
extern int __fpclassifyf(float x);
extern int __isnan(double x);
extern int __isnanf(float x);
extern int __isinf(double x);
extern int __isinff(float x);
extern int __finite(double x);
extern int __finitef(float x);
extern int __signbit(double x);
extern int __signbitf(float x);

#define fpclassify(x) \
    (sizeof(x) == sizeof(float) ? __fpclassifyf(x) : __fpclassify(x))
#define isnan(x) \
    (sizeof(x) == sizeof(float) ? __isnanf(x) : __isnan(x))
#define isinf(x) \
    (sizeof(x) == sizeof(float) ? __isinff(x) : __isinf(x))
#define isfinite(x) \
    (sizeof(x) == sizeof(float) ? __finitef(x) : __finite(x))
#define signbit(x) \
    (sizeof(x) == sizeof(float) ? __signbitf(x) : __signbit(x))
#define isnormal(x) (fpclassify(x) == FP_NORMAL)

/* Trigonometric */
extern double sin(double x);
extern float  sinf(float x);
extern double cos(double x);
extern float  cosf(float x);
extern double tan(double x);
extern float  tanf(float x);
extern double asin(double x);
extern float  asinf(float x);
extern double acos(double x);
extern float  acosf(float x);
extern double atan(double x);
extern float  atanf(float x);
extern double atan2(double y, double x);
extern float  atan2f(float y, float x);

/* Hyperbolic */
extern double sinh(double x);
extern double cosh(double x);
extern double tanh(double x);

/* Exponential / logarithmic */
extern double exp(double x);
extern float  expf(float x);
extern double exp2(double x);
extern float  exp2f(float x);
extern double expm1(double x);
extern float  expm1f(float x);
extern double log(double x);
extern float  logf(float x);
extern double log2(double x);
extern float  log2f(float x);
extern double log10(double x);
extern float  log10f(float x);
extern double log1p(double x);
extern float  log1pf(float x);
extern double pow(double x, double y);
extern float  powf(float x, float y);

/* Square root / cube root / hypotenuse */
extern double sqrt(double x);
extern float  sqrtf(float x);
extern double cbrt(double x);
extern float  cbrtf(float x);
extern double hypot(double x, double y);
extern float  hypotf(float x, float y);

/* Absolute value / sign */
extern double fabs(double x);
extern float  fabsf(float x);
extern double copysign(double x, double y);
extern float  copysignf(float x, float y);

/* Rounding */
extern double floor(double x);
extern float  floorf(float x);
extern double ceil(double x);
extern float  ceilf(float x);
extern double trunc(double x);
extern float  truncf(float x);
extern double round(double x);
extern float  roundf(float x);
extern double rint(double x);
extern float  rintf(float x);
extern double nearbyint(double x);
extern long   lrint(double x);
extern long   lround(double x);
extern long long llrint(double x);
extern long long llround(double x);

/* Remainder */
extern double fmod(double x, double y);
extern float  fmodf(float x, float y);
extern double remainder(double x, double y);
extern float  remainderf(float x, float y);

/* Fused multiply-add */
extern double fma(double x, double y, double z);
extern float  fmaf(float x, float y, float z);

/* Decomposition */
extern double frexp(double x, int *exp);
extern double ldexp(double x, int exp);
extern float  ldexpf(float x, int exp);
extern double scalbn(double x, int n);
extern float  scalbnf(float x, int n);
extern double scalbln(double x, long n);
extern float  scalblnf(float x, long n);
extern double modf(double x, double *iptr);
extern double logb(double x);
extern int    ilogb(double x);

/* Min / max / dim */
extern double fmin(double x, double y);
extern float  fminf(float x, float y);
extern double fmax(double x, double y);
extern float  fmaxf(float x, float y);
extern double fdim(double x, double y);
extern float  fdimf(float x, float y);

/* Error / gamma */
extern double erf(double x);
extern double erfc(double x);
extern double lgamma(double x);
extern double tgamma(double x);

/* NaN generation */
extern double nan(const char *tag);
extern float  nanf(const char *tag);

#endif /* __MATH_H__ */

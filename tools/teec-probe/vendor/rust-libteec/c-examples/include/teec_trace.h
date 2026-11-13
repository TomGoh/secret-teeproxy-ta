#ifndef TEEC_TRACE_H
#define TEEC_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#ifndef BINARY_PREFIX
#error "BINARY_PREFIX not defined"
#endif

/*
 * 追踪级别.
 *
 * ERROR 用于打印某种错误。
 *
 * INFO 用于打印正常文本。是默认级别。
 *
 * DEBUG 用于打印额外信息。
 *
 * FLOW 用于打印执行流，通常是函数的输入/输出。
 *
 */
#define TRACE_ERROR  1
#define TRACE_INFO   2
#define TRACE_DEBUG  3
#define TRACE_FLOW   4

#if defined(DEBUGLEVEL_0) && !defined(DEBUGLEVEL)
#define DEBUGLEVEL TRACE_ERROR
#endif

#if defined(DEBUGLEVEL_1) && !defined(DEBUGLEVEL)
#define DEBUGLEVEL TRACE_ERROR
#endif

#if defined(DEBUGLEVEL_2) && !defined(DEBUGLEVEL)
#define DEBUGLEVEL TRACE_INFO
#endif

#if defined(DEBUGLEVEL_3) && !defined(DEBUGLEVEL)
#define DEBUGLEVEL TRACE_DEBUG
#endif

#if defined(DEBUGLEVEL_4) && !defined(DEBUGLEVEL)
#define DEBUGLEVEL TRACE_FLOW
#endif

#ifndef DEBUGLEVEL
// 默认为 TRACE_INFO
#define DEBUGLEVEL TRACE_INFO
#endif

#define __PRINTFLIKE(__fmt, __varargs) __attribute__\
	((__format__(__printf__, __fmt, __varargs)))

extern void rust_dprintf(const char *function, int line, int level,
                  const char *prefix, const char *message);

static void _dprintf(const char *function, int line, int level,
                     const char *prefix, const char *fmt, ...) __PRINTFLIKE(5, 6);

/*
 * 将可变参数解析成字符串，调用 rust 的打印函数。
 *
 * @param function  调用打印函数的函数名称。
 * @param line      调用打印函数的行号。
 * @param level     追踪级别。
 * @param prefix    二进制前缀字符串。
 * @param fmt       格式字符串（printf 风格）。
 * @param ...       可变参数列表。
 *
 * @return void
 */
 /*
  * TODO: rust 的可变参数目前还不稳定，此函数将 C 的可变参数解析为字符串后再调用 rust 函数处理。
  */
static inline void _dprintf(const char *function, int line, int level,
                            const char *prefix, const char *fmt, ...)
{
    char buf[4096] = {0};
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    rust_dprintf(function, line, level, prefix, buf);
}

#define dprintf(level, x...) do { \
		if ((level) <= DEBUGLEVEL) { \
			_dprintf(__func__, __LINE__, level, \
				 BINARY_PREFIX, x); \
		} \
	} while (0)

#define EMSG(fmt, ...)   dprintf(TRACE_ERROR, fmt "\n", ##__VA_ARGS__)
#define IMSG(fmt, ...)   dprintf(TRACE_INFO, fmt "\n", ##__VA_ARGS__)
#define DMSG(fmt, ...)   dprintf(TRACE_DEBUG, fmt "\n", ##__VA_ARGS__)
#define FMSG(fmt, ...)   dprintf(TRACE_FLOW, fmt "\n", ##__VA_ARGS__)

#define INMSG(fmt, ...)  FMSG("> " fmt, ##__VA_ARGS__)
#define OUTMSG(fmt, ...) FMSG("< " fmt, ##__VA_ARGS__)
#define OUTRMSG(r)                              \
	do {                                            \
		if (r)                                      \
			EMSG("Function returns with [%d]", r);  \
		OUTMSG("r=[%d]", r);                        \
		return r;                                   \
	} while (0)

#define dprintf_raw(level, x...) do { \
		if ((level) <= DEBUGLEVEL) \
			_dprintf(0, 0, (level), BINARY_PREFIX, x); \
	} while (0)

#define EMSG_RAW(fmt, ...)   dprintf_raw(TRACE_ERROR, fmt, ##__VA_ARGS__)
#define IMSG_RAW(fmt, ...)   dprintf_raw(TRACE_INFO, fmt, ##__VA_ARGS__)
#define DMSG_RAW(fmt, ...)   dprintf_raw(TRACE_DEBUG, fmt, ##__VA_ARGS__)
#define FMSG_RAW(fmt, ...)   dprintf_raw(TRACE_FLOW, fmt, ##__VA_ARGS__)

/*
 * 此函数将十六进制和 ascii 转储缓冲区。
 *
 * 只有当 DEBUGLEVEL 是 TRACE_DEBUG 或 TRACE_FLOW 时，此函数才会打印
 *
 * @param bname     描述缓冲区的信息字符串。
 * @param buffer    指向缓冲区的指针。
 * @param blen      缓冲区的长度。
 *
 * @return void
 */
void dump_buffer(const char *bname, const uint8_t *buffer, size_t blen);

#ifdef __cplusplus
}
#endif

#endif

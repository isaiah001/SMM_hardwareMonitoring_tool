
#ifndef _COMMON_H_
#define _COMMON_H_

#include "types.h"

#define XALIGN_DOWN(x, align) (x &~ (align - 1))
#define XALIGN_UP(x, align) ((x & (align - 1)) ? XALIGN_DOWN(x, align) + align : x)

#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

#define PAGE_SHIFT 12
#define PAGE_SIZE 0x1000

// default raw image section alignment for EDK
#define DEFAULT_EDK_ALIGN 0x20

#define TO_MILLISECONDS(_seconds_) ((_seconds_) * 1000)
#define TO_MICROSECONDS(_seconds_) (TO_MILLISECONDS(_seconds_) * 1000)
#define TO_NANOSECONDS(_seconds_) (TO_MICROSECONDS(_seconds_) * 1000)

// convert GUID to string in simple way
#define GUID_STR_MAXLEN 38
#define GUID_STR(_str_, _guid_)                                                 \
                                                                                \
    tfp_sprintf((_str_), "{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X}",  \
        (_guid_)->Data1, (_guid_)->Data2, (_guid_)->Data3,                      \
        (_guid_)->Data4[0], (_guid_)->Data4[1],                                 \
        (_guid_)->Data4[2], (_guid_)->Data4[3],                                 \
        (_guid_)->Data4[4], (_guid_)->Data4[5],                                 \
        (_guid_)->Data4[6], (_guid_)->Data4[7]                                  \
    );

#define FPTR32 "0x%x"
#define FPTR64 "0x%llx"

#if defined(_M_X64) || defined(__amd64__)

#define FPTR FPTR64

#else

#define FPTR FPTR32                  

#endif
#endif

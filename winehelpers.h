#include <Windows.h>

void __inline TRACE(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    OutputDebugStringA(listp);
    va_end(listp);

}

void __inline FIXME(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    OutputDebugStringA(listp);
    va_end(listp);
}

void __inline WARN(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    OutputDebugStringA(listp);
    va_end(listp);
}

void __inline ERR(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    OutputDebugStringA(listp);
    va_end(listp);
}

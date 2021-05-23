#include <Library/UefiRuntimeLib.h>
#include <Library/BaseLib.h>

#include "config.h"
#include "HmonSmm.h"
#include "printf.h"
#include "debug.h"
//--------------------------------------------------------------------------------------
#if defined(BACKDOOR_DEBUG) //디버그가 켜져 있으면.... 말이죠...
//--------------------------------------------------------------------------------------
static char *NameFromPath(char *lpszPath)
{
    int i = 0, sep = -1;

    for (i = 0; i < AsciiStrLen(lpszPath); i += 1)
    {
        if (lpszPath[i] == '\\' || lpszPath[i] == '/')
        {
            sep = i;
        }
    }

    if (sep >= 0)
    {
        return lpszPath + sep + 1;
    }

    return lpszPath;
}
//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...) //디버그 메세지 lpszfile, int 라인, lpszmas.. 뭔지 모르겠네...
{
    va_list arglist;
    char szBuff[MAX_STR_LEN], szOutBuff[MAX_STR_LEN];

    va_start(arglist, lpszMsg);
    tfp_vsprintf(szBuff, lpszMsg, arglist);
    va_end(arglist);

    // build debug message string
    tfp_sprintf(szOutBuff, "%s(%d) : %s", NameFromPath(lpszFile), Line, szBuff); //말그대로 라인이랑 파일.... 뭐 글쌔....

    // write message into the serial port
	SmbusPrint(szOutBuff);
}
//--------------------------------------------------------------------------------------
#endif // BACKDOOR_DEBUG
//--------------------------------------------------------------------------------------
// EoF

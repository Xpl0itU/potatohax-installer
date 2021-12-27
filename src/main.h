#ifndef _MAIN_H_
#define _MAIN_H_

#include "common/types.h"
#include "common/common.h"
#include "dynamic_libs/os_functions.h"

#define MLC_MOUNT_PATH "/vol/storage_mlc01"

#define WIIUCHAT_PATH_EUR "dev:/sys/title/00050010/1005a200"
#define WIIUCHAT_PATH_USA "dev:/sys/title/00050010/1005a100"
#define WIIUCHAT_PATH_JPN "dev:/sys/title/00050010/1005a000"

#define RPX_PATH "/code/doors.rpx"
#define COS_PATH "/code/cos.rpx"

#define RPX_BACKUP_PATH "sd:/wiiu/apps/potatohax-installer/data/doors-backup.rpx"
#define POTATOHAX_RPX_PATH "sd:/wiiu/apps/potatohax-installer/data/doors.rpx"

#define COS_BACKUP_PATH "sd:/wiiu/apps/potatohax-installer/data/cos-backup.xml"
#define POTATOHAX_COS_PATH "sd:/wiiu/apps/potatohax-installer/data/cos.xml"

#define INDEX_MODE 0x644

/* Main */
#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    Undetected,
    EUR,
    USA,
    JPN
} Region;


int Menu_Main(void);
void console_printf(int newline, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif

#ifndef BOARD_REV_H
#define BOARD_REV_H

/*
Target Model : PRESTO

LINUX Kernel Define & macro function is as follows
#define CONFIG_MACH_MSM8X60_PRESTO
machine_is_msm8x60_presto() function

MODEM & LINUX User Define is T_PRESTO
*/

#define EV10  0x01
#define PT10  0x10
#define PT20  0x11
#define WS10  0x21
#define WS20  0x22
#define ES10  0x31
#define ES20  0x32
#define TP10  0x41
#define TP20  0x42
#define TP30  0x43

#define BOARD_REV TP20

#define FIRM_VER "J0000000"
#define SYS_MODEL_NAME "PRESTO"
#define SKY_MODEL_NAME "PantechP9071"

#endif /*BOARD_REV_H*/

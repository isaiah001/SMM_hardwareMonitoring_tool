
#ifndef _CONFIG_H_
#define _CONFIG_H_

#define BACKDOOR_DEBUG
#define BACKDOOR_DEBUG_SMBUS_BUILTIN

// read MSR_SMM_MCA_CAP register value ㅇㅇ
#define USE_MSR_SMM_MCA_CAP

// prit debug messages to console also 마찬가지
#define BACKDOOR_DEBUG_SERIAL_TO_CONSOLE

// SW SMI command value for communicating with backdoor SMM code 예도 확실히 노필요
#define BACKDOOR_SW_SMI_VAL 0xCC

// magic registers values for smm_call() 예도 확실히 필요 없고
#define BACKDOOR_SMM_CALL_R8_VAL 0x4141414141414141
#define BACKDOOR_SMM_CALL_R9_VAL 0x4242424242424242



#endif _CONFIG_H_

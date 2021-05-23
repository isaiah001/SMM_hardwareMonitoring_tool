#include <FrameworkSmm.h>
#include <Protocol/SmmBase.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmIoTrapDispatch2.h>

#include <Protocol/SmmPciRootBridgeIo.h>
#include <Library/UefiRuntimeLib.h>
//#include <Library/SynchronizationLib.h>
#include <Protocol/SmmPeriodicTimerDispatch.h>

#include <Library/UefiDriverEntryPoint.h>
//#include <Library/DevicePathLib.h>

#include <IndustryStandard/PeImage.h>
//#include <Library/IoLib.h>

//#include <Library/PciLib.h>
#include "../../DuetPkg/DxeIpl/X64/VirtualMemory.h"

#include "config.h"
#include "common.h"
#include "printf.h"
#include "debug.h"
#include "HmonSmm.h"


#include "serial.h"

//#pragma warning(disable: 4312)
//#pragma warning(disable: 4133)
//#pragma warning(disable: 4189)
//#pragma warning(disable: 4047)
//#pragma warning(disable: 4244)
#pragma warning(disable: 4101)
#pragma warning(disable: 4189)
typedef void* PVOID;

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* m_TextOutput = NULL;
char* m_PendingOutput = NULL;
EFI_SMM_PCI_ROOT_BRIDGE_IO_PROTOCOL* mSmmPciRootBridgeIo = NULL;
UINTN     mMMIoBaseAddress = 0;
//----------------------------------------------sound
#define EFI_SPEAKER_CONTROL_PORT       0x61
#define EFI_SPEAKER_OFF_MASK           0xFC
#define EFI_BEEP_ON_TIME_INTERVAL      0x50000
#define EFI_BEEP_OFF_TIME_INTERVAL     0x50000
//----------------------------------------------sound

#define SMBUS_IO_ADDRESS           0xF040

UINT8 pchBus = 0;
UINT8 pchDevice = 31;
UINT8 pchFunction = 3;


#define TO_MILLISECONDS(_seconds_) ((_seconds_) * 1000)
#define TO_MICROSECONDS(_seconds_) (TO_MILLISECONDS(_seconds_) * 1000)
#define TO_NANOSECONDS(_seconds_) (TO_MICROSECONDS(_seconds_) * 1000)


//--------------------------------------------------------------smbus
#define SMBUS_HSTS		 0
#define   SMBUS_BERR                (BIT3)   // BUS Error
#define   SMBUS_DERR                (BIT2)   // Device Error
#define   SMBUS_BYTE_DONE_STS       (BIT7)   // Completion Status
#define   SMBUS_BYTE_FAILD          (BIT4)   // faild
#define   SMBUS_BYTE_INTR           (BIT1)
//#define   SMBUS_BYTE_DONE_STS

#define SMBUS_HCTL       2
#define   SMBUS_START               (BIT6)   // Start/Stop
#define     SMBUS_HCTL_CMD_QUICK               0<<2
#define     SMBUS_HCTL_CMD_BYTE                1<<2
#define     SMBUS_HCTL_CMD_BYTE_DATA           2<<2
#define     SMBUS_HCTL_CMD_WORD_DATA           3<<2
#define     SMBUS_HCTL_CMD_PROCESS_CALL        4<<2
#define     SMBUS_HCTL_CMD_BLOCK               5<<2
#define     SMBUS_HCTL_CMD_i2c                 6<<2

#define SMBUS_HCMD       3
#define SMBUS_TSA		 4
#define     SMBUS_RW_SEL_READ         1
#define     SMBUS_RW_SEL_WRITE        0

#define SMBUS_HD0		 5
#define SMBUS_HD1		 6

#define SMBUS_HSTS_ALL   0b11111111
#define SMBUS_LIB_SLAVE_ADDRESS(SmBusAddress)      (((SmBusAddress) >> 1)  & 0x7f)
#define SMBUS_LIB_COMMAND(SmBusAddress)            (((SmBusAddress) >> 8)  & 0xff)
#define SMBUS_LIB_LENGTH(SmBusAddress)             (((SmBusAddress) >> 16) & 0x3f)
#define SMBUS_LIB_PEC(SmBusAddress)     ((BOOLEAN) (((SmBusAddress) & SMBUS_LIB_PEC_BIT) != 0))
#define SMBUS_LIB_RESEARVED(SmBusAddress)          ((SmBusAddress) & ~(((1 << 22) - 2) | SMBUS_LIB_PEC_BIT))
#define SMBUS_LIB_RESERVED(SmBusAddress)           ((SmBusAddress) & ~(BIT23 - 2))



//--------------------------------------------------------------------------------smbus 상수



//EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT m_PeriodicTimerDispatch2RegCtx = { 100000000, 640000 };
EFI_SMM_PERIODIC_TIMER_DISPATCH_CONTEXT m_PeriodicTimerDispatch2RegCtx = { 10000000, 640000, 10};
UINT64 m_PeriodicTimerCounter = 0;
EFI_HANDLE m_PeriodicTimerDispatchHandle = NULL;
EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL* m_PeriodicTimerDispatch = NULL;

EFI_STATUS PeriodicTimerDispatchRegister(EFI_HANDLE* DispatchHandle);
EFI_STATUS PeriodicTimerDispatchUnregister(EFI_HANDLE DispatchHandle);

UINT8 mOneTime = 0;
UINT8 alcx = 0;


//--------------------------------------------------------------------------


//---------------------------------------------------------------------timer

PVOID g_BackdoorInfo = NULL;
EFI_SYSTEM_TABLE* gST;
EFI_BOOT_SERVICES* gBS;

EFI_SMM_SYSTEM_TABLE2* gSmst = NULL;


typedef
EFI_STATUS
(EFIAPI* EFI_SMM_HANDLER_ENTRY_POINT2)(
	IN EFI_HANDLE  DispatchHandle,
	IN CONST VOID* Context         OPTIONAL,
	IN OUT VOID* CommBuffer      OPTIONAL,
	IN OUT UINTN* CommBufferSize  OPTIONAL
	);


//-----------------------------------------------------------------------smbus



UINTN
EFIAPI
SmAddrMaker(IN  UINT8 regAddr, IN  UINT8 slaveAddr)
{
	UINTN SmBusAddress;
	SmBusAddress = regAddr;
	SmBusAddress = SmBusAddress << 7;
	SmBusAddress = SmBusAddress + slaveAddr;
	SmBusAddress = SmBusAddress << 1;

	return SmBusAddress;
}


RETURN_STATUS InternalSmBusAcquire(VOID)
{
//	MmioWrite8(MMIoBaseAddress + SMBUS_HCTL, 0);
//	MmioWrite8(MMIoBaseAddress + SMBUS_HD0, 0);
//	MmioWrite8(MMIoBaseAddress + SMBUS_HD1, 0); __outbyte
//	MmioWrite8(MMIoBaseAddress + SMBUS_HSTS, SMBUS_HSTS_ALL);
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HCTL, 0);
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HD0, 0);
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HD1, 0);
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HSTS, SMBUS_HSTS_ALL);
	return RETURN_SUCCESS;
}

RETURN_STATUS InternalSmBusStart(IN  UINTN IommBaseAddress, IN  UINT8   HostControl)
{
	UINT8   HostStatus;
	UINT8   COUNT = 0;
	//
	// Set Host Control Register (Initiate Operation, Interrupt disabled).
	//
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HCTL, HostControl + SMBUS_START);

	do {
		COUNT++;
		//
		// Poll INTR bit of Host Status Register.
		//tegx
		
		HostStatus = __inbyte(SMBUS_IO_ADDRESS + SMBUS_HSTS);
		if (COUNT > 20000) {
			return RETURN_DEVICE_ERROR;
		}
	} while ((HostStatus & (SMBUS_BYTE_DONE_STS | SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD | SMBUS_BYTE_INTR)) == 0);

	if ((HostStatus & (SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD)) == 0) {
		return RETURN_SUCCESS;
	}
	//
	// Clear error bits of Host Status Register.
	//
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HSTS, (SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD));

	return RETURN_DEVICE_ERROR;
}

UINT16 InternalSmBusNonBlock(IN  UINT8 HostControl, IN  UINTN     SmBusAddress, IN  UINT16 Value, OUT RETURN_STATUS* Status)
{
	RETURN_STATUS                 ReturnStatus;

	//
	// Try to acquire the ownership of QNC SMBUS.
	//
	ReturnStatus = InternalSmBusAcquire();
	if (RETURN_ERROR(ReturnStatus)) {
		goto Done;
	}

	//
	// Set Host Commond Register.
	//SMBUS_HCMD
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HCMD, (UINT8)SMBUS_LIB_COMMAND(SmBusAddress));
	//
	// Write value to Host Data 0 and Host Data 1 Registers.
	//
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HD0, (UINT8)Value);
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HD1, (UINT8)(Value >> 8));

	// Set SMBUS slave address for the device to send/receive from.
	//
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_TSA, (UINT8)SmBusAddress);
	//
	// Start the SMBUS transaction and wait for the end.
	//
	ReturnStatus = InternalSmBusStart(SMBUS_IO_ADDRESS, HostControl);
	//
	// Read value from Host Data 0 and Host Data 1 Registers.
	//
	Value = (UINT16)(__inbyte(SMBUS_IO_ADDRESS + SMBUS_HD1) << 8);
	Value = (UINT16)(Value | __inbyte(SMBUS_IO_ADDRESS + SMBUS_HD0));

	//
	// Clear Host Status Register and Auxiliary Status Register.
	//
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HSTS, SMBUS_HSTS_ALL);

Done:
	if (Status != NULL) {
		*Status = ReturnStatus;
	}

	return Value;
}

UINT8
EFIAPI
SmBusReadDataByte(IN  UINTN          SmBusAddress, OUT RETURN_STATUS* Status  OPTIONAL)
{
	return (UINT8)InternalSmBusNonBlock(SMBUS_HCTL_CMD_BYTE_DATA, SmBusAddress | SMBUS_RW_SEL_READ, 0, Status);
}

UINT8
EFIAPI
SmBusWriteDataByte(IN  UINTN          SmBusAddress, IN  UINT8 Value, OUT RETURN_STATUS* Status        OPTIONAL)
{
	return (UINT8)InternalSmBusNonBlock(SMBUS_HCTL_CMD_BYTE_DATA, SmBusAddress | SMBUS_RW_SEL_WRITE, Value, Status);
}




//-----------------------------------------------------------------------smbus





EFI_STATUS
TurnOnSpeaker(VOID)
{
	UINT8 Data;

	Data = __inbyte(EFI_SPEAKER_CONTROL_PORT);
	Data |= 0x03;
	__outbyte(EFI_SPEAKER_CONTROL_PORT, Data);

	return EFI_SUCCESS;
}


EFI_STATUS
TurnOffSpeaker(VOID)
{
	UINT8 Data;
	

	Data = __inbyte(EFI_SPEAKER_CONTROL_PORT);
	Data &= EFI_SPEAKER_OFF_MASK;
	__outbyte(EFI_SPEAKER_CONTROL_PORT, Data);

	return EFI_SUCCESS;
}





EFI_STATUS RegisterProtocolNotifySmm(EFI_GUID* Guid, EFI_SMM_NOTIFY_FN Handler, PVOID* Registration)
{
	EFI_STATUS Status = EFI_SUCCESS;
	//EFI_STATUS Status = gBS->RegisterProtocolNotify(Guid, Handler, Registration);//레지스트레이션 자체는 의미가 없다는 거구나.. 암...
	return Status;
}


EFI_STATUS EFIAPI PeriodicTimerDispatchHandler(EFI_HANDLE DispatchHandle, EFI_SMM_PERIODIC_TIMER_DISPATCH_CONTEXT* DispatchContext)
{

	RETURN_STATUS writeState;
	UINTN SmBusAddress = 0;

	SmBusAddress = SmAddrMaker(0xD1, 0x72);
	SmBusWriteDataByte(SmBusAddress, 0x16, &writeState);

	return EFI_SUCCESS;
}

EFI_STATUS PeriodicTimerDispatchRegister(EFI_HANDLE* DispatchHandle)
{
	EFI_STATUS Status = EFI_INVALID_PARAMETER;
	
	if (m_PeriodicTimerDispatch)
	{
		
		// register periodic timer routine
		Status = m_PeriodicTimerDispatch->Register(m_PeriodicTimerDispatch, PeriodicTimerDispatchHandler, &m_PeriodicTimerDispatch2RegCtx, DispatchHandle);


		
	}

	return Status;
}

EFI_STATUS PeriodicTimerDispatchUnregister(EFI_HANDLE DispatchHandle) //언레지스터
{
	EFI_STATUS Status = EFI_INVALID_PARAMETER;

	if (m_PeriodicTimerDispatch)
	{
		// register periodic timer routine
		Status = m_PeriodicTimerDispatch->UnRegister(m_PeriodicTimerDispatch, DispatchHandle);
		if (Status == EFI_SUCCESS)
		{
			//DbgMsg(__FILE__, __LINE__, "SMM timer handler unregistered\r\n");
		}
		else
		{
			//DbgMsg(__FILE__, __LINE__, "Unregister() fails: 0x%X\r\n", Status);
		}
	}

	return Status;
}

void ConsolePrint(char* Message) //텍스트 아웃풋이 있으면 이걸 택스트 아웃풋 프로토콜로 출력하면 된다 이거십니다.
{
	UINTN Len = AsciiStrLen(Message), i = 0;

	if (m_TextOutput)
	{
		for (i = 0; i < Len; i += 1)
		{
			CHAR16 Char[2];

			Char[0] = (CHAR16)Message[i];
			Char[1] = 0;

			m_TextOutput->OutputString(m_TextOutput, Char);
		}
	}
}

void SmbusPrint(char* Message)  //시리얼 프린트.....
{
	UINTN Len = AsciiStrLen(Message), i = 0;

	//콘솔로 뽑는다 이거지....
	//SerialPortInitialize(SERIAL_PORT_NUM, SERIAL_BAUDRATE);

	//for (i = 0; i < Len; i += 1)
	//{
		// send single byte via serial port
	//	SerialPortWrite(SERIAL_PORT_NUM, Message[i]);

	//}


	if (m_TextOutput == NULL)
	{
		if (m_PendingOutput && AsciiStrLen(m_PendingOutput) + AsciiStrLen(Message) < PAGE_SIZE)
		{
			// text output protocol is not initialized yet, save output to temp buffer 탬프러리 버퍼에 저장하는 것....
			AsciiStrCat(m_PendingOutput, Message); //strcat m_pendingoutput, message,
		}
	}
	else
	{
		ConsolePrint(Message);
	}

}

EFI_STATUS EFIAPI PeriodicTimerDispatchProtocolNotifyHandler(EFI_EVENT Event, PVOID Context)
{
	EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL* PeriodicTimerDispatch = NULL;
	//m_PeriodicTimerDispatch = (EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL*)Interface;
	gBS->LocateProtocol(&gEfiSmmPeriodicTimerDispatchProtocolGuid, NULL, &PeriodicTimerDispatch);
	m_PeriodicTimerDispatch = PeriodicTimerDispatch;
	//PeriodicTimerDispatchRegister(&m_PeriodicTimerDispatchHandle);

	return EFI_SUCCESS;
}






int memcmp(const void* s1, const void* s2, size_t n)
{
	const unsigned char* p1 = s1, * p2 = s2;
	while (n--)
		if (*p1 != *p2)
			return *p1 - *p2;
		else
			p1++, p2++;
	return 0;
}

#define AMI_USB_SMM_PROTOCOL_GUID { 0x3ef7500e, 0xcf55, 0x474f, \
                                    { 0x8e, 0x7e, 0x00, 0x9e, 0x0e, 0xac, 0xec, 0xd2 }}

EFI_LOCATE_PROTOCOL old_SmmLocateProtocol = NULL;




EFI_STATUS EFIAPI new_SmmLocateProtocol(
	EFI_GUID* Protocol,
	VOID* Registration,
	VOID** Interface)
{
	EFI_GUID TargetGuid = AMI_USB_SMM_PROTOCOL_GUID;

	/*
		Totally board-specific hack for Intel DQ77KB, SmmLocateProtocol
		with AMI_USB_SMM_PROTOCOL_GUID is calling during OS startup after
		APIC init, so, here we can register our SMI timer.
	*/
	if (Protocol && !memcmp(Protocol, &TargetGuid, sizeof(TargetGuid)))
	{
		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"()\r\n");

		if (m_PeriodicTimerDispatchHandle)
		{
			// unregister previously registered timer
			PeriodicTimerDispatchUnregister(m_PeriodicTimerDispatchHandle);
			m_PeriodicTimerDispatchHandle = NULL;
		}

		// enable periodic timer SMI again
		PeriodicTimerDispatchRegister(&m_PeriodicTimerDispatchHandle); 

		// remove the hook
		gSmst->SmmLocateProtocol = old_SmmLocateProtocol;
	}

	return old_SmmLocateProtocol(Protocol, Registration, Interface);
}

EFI_STATUS RegisterProtocolNotifyDxe( //프로토콜 노티파이 dex 등록....
	EFI_GUID* Guid, EFI_EVENT_NOTIFY Handler,//노티파이 핸들러를 받아서
	EFI_EVENT* Event, PVOID* Registration)
{
	EFI_STATUS Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, Handler, NULL, Event); //헨들러를 넣어서 이벤트로 만들고...
	if (EFI_ERROR(Status))
	{
		//DbgMsg(__FILE__, __LINE__, "CreateEvent() fails: 0x%X\r\n", Status);
		return Status;
	}

	Status = gBS->RegisterProtocolNotify(Guid, *Event, (PVOID)Registration);//그 이벤드를 등록한다..
	if (EFI_ERROR(Status))
	{
		//DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() fails: 0x%X\r\n", Status);
		return Status;
	}

	//DbgMsg(__FILE__, __LINE__, "Protocol notify handler is at "FPTR"\r\n", Handler);

	return Status;
}

VOID HmonEntrySmm(VOID)
{
	PVOID Registration = NULL;
	EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL* PeriodicTimerDispatch = NULL;

	
	EFI_STATUS Status = gBS->LocateProtocol(&gEfiSmmPeriodicTimerDispatchProtocolGuid, NULL, &PeriodicTimerDispatch);
	if (Status == EFI_SUCCESS)//있으면 핸들러를 바로 부르고..
	{
		// protocol is already present, call handler directly
		m_PeriodicTimerDispatch = PeriodicTimerDispatch;
		//PeriodicTimerDispatchProtocolNotifyHandler(&gEfiSmmPeriodicTimerDispatchProtocolGuid, PeriodicTimerDispatch, NULL);
	}
	else
	{
		EFI_EVENT Event = NULL;
		RegisterProtocolNotifyDxe(&gEfiSmmPeriodicTimerDispatchProtocolGuid, PeriodicTimerDispatchProtocolNotifyHandler, &Event, &Registration);
		//REGISTER_NOTIFY(PeriodicTimerDispatch);
	}
	//RegisterProtocolNotifySmm(&gEfiSmmPeriodicTimerDispatchProtocolGuid,   PeriodicTimerDispatchProtocolNotifyHandler, &Registration)


	old_SmmLocateProtocol = gSmst->SmmLocateProtocol;
	gSmst->SmmLocateProtocol = new_SmmLocateProtocol;
}

//노티파이가 왔을때 여기로 온다는게 등록이 되었으므로... 
// 등록한것과는 별개로 이미 프로토콜이 존재한다면 여기로 오면 된다는 거시에요.





BOOLEAN ConsoleInit(void)
{
	if (m_PendingOutput == NULL)
	{
		EFI_PHYSICAL_ADDRESS PagesAddr;

		// allocate memory for pending debug output 매모리를 만들고...
		EFI_STATUS Status = gBS->AllocatePages(
			AllocateAnyPages,
			EfiRuntimeServicesData,
			1, &PagesAddr
		);
		if (EFI_ERROR(Status))
		{
			DbgMsg(__FILE__, __LINE__, "AllocatePages() fails: 0x%X\r\n", Status);
			return FALSE;
		}

		m_PendingOutput = (char*)PagesAddr;
		gBS->SetMem(m_PendingOutput, PAGE_SIZE, 0);
	}

	return TRUE;
}



VOID SimpleTextOutProtocolNotifyHandler(EFI_EVENT Event, PVOID Context)
{
	EFI_STATUS Status = EFI_SUCCESS;


	// initialize serial port again if it wasn't available 나한태는 필요가 없습니다.
	if (m_TextOutput == NULL) //없으면... 택스트 아웃풋 guid 포인터
	{
		// initialize console I/O
		Status = gBS->HandleProtocol(gST->ConsoleOutHandle, &gEfiSimpleTextOutProtocolGuid, (PVOID*)& m_TextOutput);
		if (Status == EFI_SUCCESS)
		{
			m_TextOutput->SetAttribute(m_TextOutput, EFI_TEXT_ATTR(EFI_WHITE, EFI_RED));
			m_TextOutput->ClearScreen(m_TextOutput);

			// print pending messages
			if (m_PendingOutput)
			{
				EFI_PHYSICAL_ADDRESS PagesAddr = (EFI_PHYSICAL_ADDRESS)m_PendingOutput;
				ConsolePrint(m_PendingOutput);
				gBS->FreePages(PagesAddr, 1);
				m_PendingOutput = NULL;

				gBS->Stall(TO_MICROSECONDS(1));
			}
		}
	}



	DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Protocol ready\r\n");
}



EFI_STATUS
HmonEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable) {
	
	gST = SystemTable;
	gBS = gST->BootServices;
	EFI_STATUS Status = EFI_SUCCESS;
	BOOLEAN bInSmram = FALSE;
	EFI_SMM_BASE2_PROTOCOL* SmmBase2 = NULL;


	
	
	//EFI_SMM_BASE_PROTOCOL* SmmBase = NULL;//base1
	//Status = gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase); //base1
	Status = gBS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, NULL, &SmmBase2);
	if (Status == EFI_SUCCESS) {
		SmmBase2->InSmm(SmmBase2, &bInSmram);
	}else{
		
	}
		if (bInSmram) {
		
		
		
		Status = SmmBase2->GetSmstLocation(SmmBase2, &gSmst);

		if (Status == EFI_SUCCESS){
			//PciLibConstructor();
			HmonEntrySmm();
		}

	}
	else {
			PVOID Registration = NULL;
			EFI_EVENT Event = NULL;
			ConsoleInit();



			RegisterProtocolNotifyDxe(&gEfiSimpleTextOutProtocolGuid, SimpleTextOutProtocolNotifyHandler, &Event, &Registration);

	}
	return EFI_SUCCESS;
}


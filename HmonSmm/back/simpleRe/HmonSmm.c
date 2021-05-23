#include <FrameworkSmm.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/SmmCpu.h>

#include <Protocol/SmmBase.h>

#include <Protocol/SmmSwDispatch2.h>

#include <Protocol/SmmEndOfDxe.h>
#include <Protocol/DevicePath.h>

#include <Library/IoLib.h>

#include <Library/UefiDriverEntryPoint.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Library/DevicePathLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/PciLib.h>
#include <IndustryStandard/PeImage.h>
#include <Library/DebugLib.h>

#include <Protocol/SmmPeriodicTimerDispatch2.h>
#include <Library/PciHostBridgeLib.h>

#include <Library/TimerLib.h>
#include <Library/UefiLib.h>

//#pragma warning(disable: 4312)
//#pragma warning(disable: 4133)
//#pragma warning(disable: 4189)
//#pragma warning(disable: 4047)
//#pragma warning(disable: 4244)
#pragma warning(disable: 4101)
#pragma warning(disable: 4189)

//--------------------------------------------------beep/
#define EFI_SPEAKER_CONTROL_PORT       0x61
#define EFI_SPEAKER_OFF_MASK           0xFC
#define EFI_BEEP_ON_TIME_INTERVAL      0x50000
#define EFI_BEEP_OFF_TIME_INTERVAL     0x50000


#define TO_MILLISECONDS(_seconds_) ((_seconds_) * 1000)
#define TO_MICROSECONDS(_seconds_) (TO_MILLISECONDS(_seconds_) * 1000)
#define TO_NANOSECONDS(_seconds_) (TO_MICROSECONDS(_seconds_) * 1000)

typedef void* PVOID;

UINT8 pchBus = 0;
UINT8 pchDevice = 31;
UINT8 pchFunction = 3;
EFI_SYSTEM_TABLE* mgST = NULL;
EFI_BOOT_SERVICES* mgBS = NULL;
EFI_SMM_SYSTEM_TABLE2* gSmst = NULL;

//EFI_SMM_SYSTEM_TABLE2* gST2 = NULL;
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* m_TextOutput = NULL;


EFI_STATUS PeriodicTimerDispatch2Register(EFI_HANDLE* DispatchHandle);
EFI_STATUS PeriodicTimerDispatch2Unregister(EFI_HANDLE DispatchHandle);

EFI_HANDLE m_PeriodicTimerDispatchHandle = NULL;
EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL* m_PeriodicTimerDispatch = NULL;


EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT m_PeriodicTimerDispatch2RegCtx = { 1000000, 640000 };
//--------------------------------------------------------------편의  도구
#define TO_MILLISECONDS(_seconds_) ((_seconds_) * 1000)
#define TO_MICROSECONDS(_seconds_) (TO_MILLISECONDS(_seconds_) * 1000)
#define TO_NANOSECONDS(_seconds_) (TO_MICROSECONDS(_seconds_) * 1000)
//--------------------------------------------------------------편의  도구
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

UINT8 smMarker = 0;
//----------------------------------------------------------------------smbus 시작
typedef struct {
	UINTN Signature;
	EFI_EVENT PeriodicTimer;
	EFI_EVENT OneShotTimer;
	//
	// Other device specific fields
	//
} EXAMPLE_DEVICE;


int memcmp(const void* s1, const void* s2, size_t n)
{
unsigned char* ps1, * ps2;
unsigned int n1, n2;

 int i;



	   ps1 = (unsigned char*)s1;

	     ps2 = (unsigned char*)s2;

	

		     for (i = 0; i < n; i++)

		     {

		         n1 = *ps1++;

		         n2 = *ps2++;

		        if (n1 != n2)

			        {

			            if (n1 > n2)

				            {

				                return 1;

			             }

			            else

				            {

				                return -1;

			             }

		         }

		    }

	     return 0;

	 }


UINT32 GetPciAddress(UINT8   Segment, UINT8   Bus, UINT8   DevFunc, UINT8   Register)
{
	UINT32  Data;
	Data = (((UINT32)Segment) << 24);
	Data |= (((UINT32)Bus) << 16);
	Data |= (((UINT32)DevFunc) << 8);
	Data |= (UINT32)Register;
	return Data;
}

UINTN InternalGetSmbusIoPortBaseAddress(VOID)
{
	UINTN     MMIoBaseAddress;
	UINTN PciAddress = 0;
	PciAddress = PCI_LIB_ADDRESS(pchBus, pchDevice, pchFunction, 16);
	MMIoBaseAddress = PciRead32(PciAddress);
	MMIoBaseAddress = MMIoBaseAddress - 4;
	return MMIoBaseAddress;
}

RETURN_STATUS InternalSmBusAcquire(UINTN MMIoBaseAddress)
{
	// Clear host status register and exit. 레지스터에 기록하고 빠져 나오는거심니다.
	MmioWrite8(MMIoBaseAddress + SMBUS_HCTL, 0);
	//Print(L"%2X HCTL and ", MmioRead8(MMIoBaseAddress + SMBUS_HCTL));
	MmioWrite8(MMIoBaseAddress + SMBUS_HD0, 0);
	MmioWrite8(MMIoBaseAddress + SMBUS_HD1, 0);
	MmioWrite8(MMIoBaseAddress + SMBUS_HSTS, SMBUS_HSTS_ALL);
	return RETURN_SUCCESS;
}

RETURN_STATUS InternalSmBusStart(IN  UINTN IommBaseAddress,IN  UINT8   HostControl)
{
	UINT8   HostStatus;
	UINT8   COUNT = 0;
	//
	// Set Host Control Register (Initiate Operation, Interrupt disabled).
	//
	MmioWrite8(IommBaseAddress + SMBUS_HCTL, HostControl + SMBUS_START);

	do {
		COUNT++;
		//
		// Poll INTR bit of Host Status Register.
		//tegx
		gBS->Stall(200);
		HostStatus = MmioRead8(IommBaseAddress + SMBUS_HSTS);
		if (COUNT > 2000) {
			return RETURN_DEVICE_ERROR;
		}
	} while ((HostStatus & (SMBUS_BYTE_DONE_STS | SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD | SMBUS_BYTE_INTR)) == 0);

	if ((HostStatus & (SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD)) == 0) {
		return RETURN_SUCCESS;
	}
	//
	// Clear error bits of Host Status Register.
	//
	MmioWrite8(IommBaseAddress + SMBUS_HSTS, (SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD));

	return RETURN_DEVICE_ERROR;
}

UINT16 InternalSmBusNonBlock(IN  UINT8 HostControl,IN  UINTN     SmBusAddress,IN  UINT16 Value,	OUT RETURN_STATUS* Status)
{
	RETURN_STATUS                 ReturnStatus;
	UINTN                         MMIoBaseAddress;

	MMIoBaseAddress = InternalGetSmbusIoPortBaseAddress();

	//
	// Try to acquire the ownership of QNC SMBUS.
	//
	ReturnStatus = InternalSmBusAcquire(MMIoBaseAddress);
	if (RETURN_ERROR(ReturnStatus)) {
		goto Done;
	}

	//
	// Set Host Commond Register.
	//SMBUS_HCMD
	MmioWrite8(MMIoBaseAddress + SMBUS_HCMD, (UINT8)SMBUS_LIB_COMMAND(SmBusAddress));
	//
	// Write value to Host Data 0 and Host Data 1 Registers.
	//
	MmioWrite8(MMIoBaseAddress + SMBUS_HD0, (UINT8)Value);
	MmioWrite8(MMIoBaseAddress + SMBUS_HD1, (UINT8)(Value >> 8));

	// Set SMBUS slave address for the device to send/receive from.
	//
	MmioWrite8(MMIoBaseAddress + SMBUS_TSA, (UINT8)SmBusAddress);
	//
	// Start the SMBUS transaction and wait for the end.
	//
	ReturnStatus = InternalSmBusStart(MMIoBaseAddress, HostControl);
	//
	// Read value from Host Data 0 and Host Data 1 Registers.
	//
	Value = (UINT16)(MmioRead8(MMIoBaseAddress + SMBUS_HD1) << 8);
	Value = (UINT16)(Value | MmioRead8(MMIoBaseAddress + SMBUS_HD0));

	//
	// Clear Host Status Register and Auxiliary Status Register.
	//
	MmioWrite8(MMIoBaseAddress + SMBUS_HSTS, SMBUS_HSTS_ALL);

Done:
	if (Status != NULL) {
		*Status = ReturnStatus;
	}

	return Value;
}

UINT8
EFIAPI
SmBusReadDataByte(
	IN  UINTN          SmBusAddress,
	OUT RETURN_STATUS* Status        OPTIONAL
)
{
	//ASSERT(SMBUS_LIB_LENGTH(SmBusAddress) == 0);
	//ASSERT(SMBUS_LIB_RESERVED(SmBusAddress) == 0);

	return (UINT8)InternalSmBusNonBlock(SMBUS_HCTL_CMD_BYTE_DATA, SmBusAddress | SMBUS_RW_SEL_READ, 0, Status);
}


UINT8
EFIAPI
SmBusWriteDataByte(IN  UINTN SmBusAddress, IN  UINT8 Value, OUT RETURN_STATUS* Status        OPTIONAL)
{
	//ASSERT(SMBUS_LIB_LENGTH(SmBusAddress) == 0);
	//ASSERT(SMBUS_LIB_RESERVED(SmBusAddress) == 0);
	return (UINT8)InternalSmBusNonBlock(SMBUS_HCTL_CMD_BYTE_DATA, SmBusAddress | SMBUS_RW_SEL_WRITE, Value, Status);
}



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






EFI_DEVICE_PATH_PROTOCOL* _AppendDevicePath(IN EFI_DEVICE_PATH_PROTOCOL* Src1, IN EFI_DEVICE_PATH_PROTOCOL* Src2)
{
	EFI_STATUS Status;
	UINTN Size;
	UINTN Size1;
	UINTN Size2;
	EFI_DEVICE_PATH_PROTOCOL* NewDevicePath; 
	EFI_DEVICE_PATH_PROTOCOL* SecondDevicePath;
	//// Allocate space for the combined device path. It only has one end node 	of
	// length EFI_DEVICE_PATH_PROTOCOL 
	//
	Size1 = GetDevicePathSize(Src1);
	Size2 = GetDevicePathSize(Src2);
	Size = Size1 + Size2;
	if (Size1 != 0 && Size2 != 0) {
		Size -= sizeof(EFI_DEVICE_PATH_PROTOCOL);
	}
	Status = gBS->AllocatePool(EfiBootServicesData, Size, (VOID * *)& NewDevicePath);

	if (EFI_ERROR(Status)) {
		return NULL;
	}
	gBS->CopyMem(NewDevicePath, Src1, Size1);	//// Over write Src1 EndNode and do the copy 

	if (Size1 != 0) {
		SecondDevicePath = (EFI_DEVICE_PATH_PROTOCOL*)((CHAR8*)NewDevicePath + (Size1 - sizeof(EFI_DEVICE_PATH_PROTOCOL)));
	}
	else {
		SecondDevicePath = NewDevicePath;
	}
	gBS->CopyMem(SecondDevicePath, Src2, Size2);
	return NewDevicePath;
}

EFI_STATUS EFIAPI PeriodicTimerDispatch2Handler( //여기가 진정한 본체구나...
	EFI_HANDLE DispatchHandle, CONST VOID* Context,
	VOID* CommBuffer, UINTN* CommBufferSize)
{
	EFI_STATUS Status = EFI_SUCCESS;

	UINT8 Data;
	Data = __inbyte(EFI_SPEAKER_CONTROL_PORT);
	Data |= 0x03;
	__outbyte(EFI_SPEAKER_CONTROL_PORT, Data);
	
	//EFI_SMM_CPU_PROTOCOL* SmmCpu = NULL;
	/*
	if (g_BackdoorInfo == NULL)
	{
		// we need this structure for communicating with the outsude world
		goto _end;
	}

	m_PeriodicTimerCounter += 1;
	g_BackdoorInfo->TicksCount = m_PeriodicTimerCounter;

	Status = gSmst->SmmLocateProtocol(&gEfiSmmCpuProtocolGuid, NULL, (PVOID*)& SmmCpu);
	if (Status == EFI_SUCCESS)
	{
		CONTROL_REGS ControlRegs;
		UINT64 Rax = 0, Rcx = 0, Rdx = 0, Rdi = 0, Rsi = 0, R8 = 0, R9 = 0;

		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_CR0, ControlRegs.Cr0);
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_CR3, ControlRegs.Cr3);
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_CR4, ControlRegs.Cr4);
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RCX, Rcx); // user-mode instruction pointer
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RDI, Rdi); // 1-st param (code)
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RSI, Rsi); // 2-nd param (arg1)
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RDX, Rdx); // 3-rd param (arg2)
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_R8, R8);
		READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_R9, R9);

		
		//	Check for magic values that was set in smm_call(),
		//	see smm_call/smm_call.asm for more info.
		
		if (R8 == BACKDOOR_SMM_CALL_R8_VAL && R9 == BACKDOOR_SMM_CALL_R9_VAL)
		{
			DbgMsg(
				__FILE__, __LINE__,
				"smm_call(): CPU #%d, RDI = 0x%llx, RSI = 0x%llx, RDX = 0x%llx\r\n",
				gSmst->CurrentlyExecutingCpu, Rdi, Rsi, Rdx
			);

			// handle backdoor control request
			Status = SmmCallHandle(Rdi, Rsi, Rdx, &ControlRegs);

			// set smm_call() return value
			WRITE_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RAX, Rax, Status);

			// let smm_call() to exit from infinite loop
			WRITE_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RCX, Rcx, Rcx - MAX_JUMP_SIZE);
		}
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "LocateProtocol() fails: 0x%X\r\n", Status);
	}
	
_end:
*/
	return EFI_SUCCESS;
}

EFI_STATUS PeriodicTimerDispatch2Register(EFI_HANDLE* DispatchHandle)
{//레지스터
	EFI_STATUS Status = EFI_INVALID_PARAMETER;

	if (m_PeriodicTimerDispatch)
	{
		// register periodic timer routine
		Status = m_PeriodicTimerDispatch->Register(
			m_PeriodicTimerDispatch,
			PeriodicTimerDispatch2Handler,
			&m_PeriodicTimerDispatch2RegCtx,
			DispatchHandle
		);
		if (Status == EFI_SUCCESS)
		{
			/*
			DbgMsg(
				__FILE__, __LINE__, "SMM timer handler is at "FPTR"\r\n",
				PeriodicTimerDispatch2Handler
			);
			*/
		}
		else
		{
			/*
			DbgMsg(__FILE__, __LINE__, "Register() fails: 0x%X\r\n", Status);
			*/
		}
	}

	return Status;
}

EFI_STATUS PeriodicTimerDispatch2Unregister(EFI_HANDLE DispatchHandle) //언레지스터
{
	EFI_STATUS Status = EFI_INVALID_PARAMETER;

	if (m_PeriodicTimerDispatch)
	{
		// register periodic timer routine
		Status = m_PeriodicTimerDispatch->UnRegister(
			m_PeriodicTimerDispatch,
			DispatchHandle
		);
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
			PeriodicTimerDispatch2Unregister(m_PeriodicTimerDispatchHandle);
			m_PeriodicTimerDispatchHandle = NULL;
		}

		// enable periodic timer SMI again
		PeriodicTimerDispatch2Register(&m_PeriodicTimerDispatchHandle);

		// remove the hook
		gSmst->SmmLocateProtocol = old_SmmLocateProtocol;
	}

	return old_SmmLocateProtocol(Protocol, Registration, Interface);
}


EFI_STATUS EFIAPI PeriodicTimerDispatch2ProtocolNotifyHandler(CONST EFI_GUID* Protocol, VOID* Interface, EFI_HANDLE Handle)
{
	EFI_STATUS Status = EFI_SUCCESS;
	UINT64* SmiTickInterval = NULL;

	m_PeriodicTimerDispatch = (EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL*)Interface;

#if defined(BACKDOOR_DEBUG)

	SerialPrint("Supported timer intervals:");

	do
	{
		Status = m_PeriodicTimerDispatch->GetNextShorterInterval(
			m_PeriodicTimerDispatch,
			&SmiTickInterval
		);
		if (Status == EFI_SUCCESS)
		{
			if (*SmiTickInterval < 0x80000000)
			{
				char szBuff[0x20];

				// build debug message string
				tfp_sprintf(szBuff, " %lld", *SmiTickInterval);
				SerialPrint(szBuff);
			}
		}
		else
		{
			break;
		}
	} while (SmiTickInterval);

	SerialPrint("\r\n");

#endif
	return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EndOfDxeProtocolNotifyHandler(CONST EFI_GUID* Protocol,VOID* Interface,EFI_HANDLE Handle)
{
	/*
	if (g_BackdoorInfo)
	{
		UINTN Offset = 0, i = 0;
		PUCHAR Buff = (PUCHAR)RVATOVA(g_BackdoorInfo, PAGE_SIZE);

		// enumerate available SMRAM regions
		for (;;)
		{
			EFI_SMRAM_DESCRIPTOR* Info = &g_BackdoorInfo->SmramMap[i];

			if (Info->PhysicalStart == 0 || Info->PhysicalSize == 0)
			{
				// end of the list
				break;
			}

			if (Offset + Info->PhysicalSize <= MAX_SMRAM_SIZE)
			{
				// copy SMRAM region into the backdoor info structure
				gBS->CopyMem(Buff + Offset, (VOID*)Info->PhysicalStart, Info->PhysicalSize);
			}
			else
			{
				break;
			}

			Offset += Info->PhysicalSize;
			i += 1;
		}


	}
	*/
	return EFI_SUCCESS;
}


EFI_STATUS RegisterProtocolNotifySmm(EFI_GUID* Guid, EFI_SMM_NOTIFY_FN Handler, PVOID* Registration)
{
	EFI_STATUS Status = gSmst->SmmRegisterProtocolNotify(Guid, Handler, Registration);//레지스트레이션 자체는 의미가 없다는 거구나.. 암...
	if (Status == EFI_SUCCESS)
	{
		//DbgMsg(__FILE__, __LINE__, "SMM protocol notify handler is at "FPTR"\r\n", Handler);
	}
	else
	{
		//DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() fails: 0x%X\r\n", Status);
	}

	return Status;
}



VOID
TimerHandler(
	IN EFI_EVENT  Event,
	IN VOID* Context
)
{
	//UINTN SmBusAddress = 0;
	//UINT8 byteDexEx = 12;
	//RETURN_STATUS writeState;
	//SmBusAddress = SmAddrMaker(0xE1, 0x72);
	//SmBusWriteDataByte(SmBusAddress, byteDexEx, &writeState);
}



EFI_STATUS
HmonEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable) {
	
	mgST = SystemTable;
	mgBS = mgST->BootServices;
	/*
	mgBS->Stall(TO_MICROSECONDS(5));
	UINT8 Data;
	Data = IoRead8(EFI_SPEAKER_CONTROL_PORT);
	Data |= 0x03;
	IoWrite8(EFI_SPEAKER_CONTROL_PORT, Data);
	
	EFI_SMM_BASE_PROTOCOL* SmmBase = NULL;
	EFI_STATUS Status = EFI_SUCCESS;
	BOOLEAN bInSmram = TRUE;




	gST = SystemTable;
	gBS = gST->BootServices;
	Status = gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase);

	SmmBase->InSmm(SmmBase, &bInSmram);

	//EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
	//EFI_DEVICE_PATH_PROTOCOL* ImageDevicePath;
	//EFI_DEVICE_PATH_PROTOCOL* CompleteFilePath;
	
	EFI_HANDLE Handle = NULL;
	gBS->Stall(TO_MICROSECONDS(5));
	UINT8 Data;
	Data = IoRead8(EFI_SPEAKER_CONTROL_PORT);
	Data |= 0x03;
	IoWrite8(EFI_SPEAKER_CONTROL_PORT, Data);
	gBS->Stall(TO_MICROSECONDS(5));

	
	if (bInSmram) {
		
		Data = IoRead8(EFI_SPEAKER_CONTROL_PORT);
		Data |= 0x03;
		IoWrite8(EFI_SPEAKER_CONTROL_PORT, Data);
		gBS->Stall(TO_MICROSECONDS(5));

		PVOID Registration = NULL;
		EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL* PeriodicTimerDispatch = NULL;
	    #define REGISTER_NOTIFY(_name_)  RegisterProtocolNotifySmm(&gEfiSmm##_name_##ProtocolGuid,_name_##ProtocolNotifyHandler, &Registration)
		//이게 도테제 워냐??

		Status = gSmst->SmmLocateProtocol(&gEfiSmmPeriodicTimerDispatch2ProtocolGuid, NULL,&PeriodicTimerDispatch);

		if (Status == EFI_SUCCESS)//있으면 핸들러를 바로 부르고..
		{
			// protocol is already present, call handler directly
			PeriodicTimerDispatch2ProtocolNotifyHandler(
				&gEfiSmmPeriodicTimerDispatch2ProtocolGuid,
				PeriodicTimerDispatch, NULL
			);
		}
		else
		{
			// set registration notifications for required SMM protocol
			//아니면 레지스트레이션 노티피케이션으로 smm 프로토콜을 요구한다..
			REGISTER_NOTIFY(PeriodicTimerDispatch2);
		}

		REGISTER_NOTIFY(EndOfDxe);

		old_SmmLocateProtocol = gSmst->SmmLocateProtocol;
		gSmst->SmmLocateProtocol = new_SmmLocateProtocol;

	}
	else {
	
		if (ImageHandle != NULL) {
			gBS->Stall(TO_MICROSECONDS(5));
			
			Data = IoRead8(EFI_SPEAKER_CONTROL_PORT);
			Data |= 0x03;
			IoWrite8(EFI_SPEAKER_CONTROL_PORT, Data);
			gBS->Stall(TO_MICROSECONDS(5));
			/*
			Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID*)& LoadedImage);
			Status = gBS->HandleProtocol(LoadedImage->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID*)& ImageDevicePath);
			CompleteFilePath = _AppendDevicePath(ImageDevicePath, LoadedImage->FilePath);
			Status = SmmBase->Register(SmmBase, CompleteFilePath, NULL, 0, &Handle, FALSE);
			//어짜피 디버그가 불가능 합니다.
			
		}


		return EFI_SUCCESS;
	}
	*/
	//w518519352
	return EFI_SUCCESS;
}


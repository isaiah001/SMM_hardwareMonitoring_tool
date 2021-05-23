#include <FrameworkSmm.h>
#include <Protocol/SmmBase.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmIoTrapDispatch2.h>
#include <Protocol/SmmPciRootBridgeIo.h>
#include <Protocol/SmmPeriodicTimerDispatch.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/IoLib.h>


#include <IndustryStandard/PeImage.h>
#include "HmonSmm.h"



#pragma warning(disable: 4244)
#pragma warning(disable: 4101)
#pragma warning(disable: 4189)
typedef void* PVOID;


//-----------------------------------------------------------------------------------LPC adrress stup
#define DEFAULT_PCI_BUS_NUMBER_PCH      0
#define R_PCH_LPC_ACPI_BASE             0x40
#define PCI_DEVICE_NUMBER_PCH_LPC       31   //LPC D31 F0
#define B_PCH_LPC_ACPI_BASE_BAR         0x0000FF80

#define PCI_DEVICE_NUMBER_PCH_SMBUS       31 
#define PCI_FUNCTION_NUMBER_PCH_SMBUS      3
//------------------------------------------------------------------------------------end lpc


#define SMBUS_IO_ADDRESS           0xF040


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

#define SMBUS_HCTL       2					  // Host Control Register R/W
#define   SMBUS_START               (BIT6)   // Start/Stop
#define     SMBUS_HCTL_CMD_QUICK               0<<2
#define     SMBUS_HCTL_CMD_BYTE                1<<2
#define     SMBUS_HCTL_CMD_BYTE_DATA           2<<2
#define     SMBUS_HCTL_CMD_WORD_DATA           3<<2
#define     SMBUS_HCTL_CMD_PROCESS_CALL        4<<2
#define     SMBUS_HCTL_CMD_BLOCK               5<<2
#define     SMBUS_HCTL_CMD_i2c                 6<<2

#define SMBUS_HCMD       3						// Host Command Register R/W
#define SMBUS_TSA		 4						// Command to be transmitted
#define     SMBUS_RW_SEL_READ         1				// Direction of the host transfer, 1 = read, 0 = write
#define     SMBUS_RW_SEL_WRITE        0

#define SMBUS_HD0		 5					// Data 0 Register R/W
#define SMBUS_HD1		 6					// Data 1 Register R/W


#define SMBUS_HBD                   0x07 
#define SMBUS_AUXC                  0x0D
#define SMBUS_AUXS                  0x0C  // Auxiliary Status Register R/WC

#define SMBUS_LIB_PEC_BIT   (1 << 22)

#define SMBUS_HSTS_ALL   0b11111111
#define SMBUS_LIB_SLAVE_ADDRESS(SmBusAddress)      (((SmBusAddress) >> 1)  & 0x7f)
#define SMBUS_LIB_COMMAND(SmBusAddress)            (((SmBusAddress) >> 8)  & 0xff)
#define SMBUS_LIB_LENGTH(SmBusAddress)             (((SmBusAddress) >> 16) & 0x3f)
#define SMBUS_LIB_PEC(SmBusAddress)     ((BOOLEAN) (((SmBusAddress) & SMBUS_LIB_PEC_BIT) != 0))
#define SMBUS_LIB_RESEARVED(SmBusAddress)          ((SmBusAddress) & ~(((1 << 22) - 2) | SMBUS_LIB_PEC_BIT))
#define SMBUS_LIB_RESERVED(SmBusAddress)           ((SmBusAddress) & ~(BIT23 - 2))

#define SMBUS_SSTS                   0x10  // Slave Status Register R/WC
#define SMBUS_SCMD                   0x11  // Slave Command Register R/W
#define SMBUS_E32B                  0x02


#define SMBUS_NDA                    0x14  // Notify Device Address Register RO
#define SMBUS_NDLB                   0x16  // Notify Data Low Byte Register RO
#define SMBUS_NDHB                   0x17  // Notify Data High Byte Register RO
#define B_PCH_SMBUS_HSTS_ALL              0xFF
#define B_PCH_SMBUS_CRCE                  0x01
#define B_PCH_SMBUS_AAC                   0x01
#define B_PCH_SMBUS_PEC_EN                0x80

#define SMBUS_SMB_CMD_BLOCK         0x14

//--------------------------------------------------------------------------------smbus 상수
#define EC_REG_BASE			0x029C
#define EC_REG_DEVID			0x20	/* Device ID (2 bytes) */
#define EC_IT8518_ID			0x8518
#define EC_IT8528_ID			0x8528

#define IT8518_CMD_PORT			0x029E
#define IT8518_DAT_PORT			0x029F

#define EC_MAX_GPIO_NUM			8UL
#define EC_MAX_ADC_NUM			5UL
#define EC_MAX_FAN_NUM			3UL
#define EC_MAX_BLC_NUM			2UL
#define EC_MAX_SMB_NUM			4UL
#define EC_MAX_WDT_NUM			2UL
#define EC_MAX_DID			32UL

#define SCALE_IN	2933
#define EC_DELAY_MIN			200UL
#define EC_DELAY_MAX			250UL

#define EC_MAX_RETRIES			400UL

//* iManager commands

#define EC_CMD_CHK_RDY			0UL
#define EC_CMD_HWP_RD			0x11UL
#define EC_CMD_HWP_WR			0x12UL
#define EC_CMD_GPIO_DIR_RD		0x30UL
#define EC_CMD_GPIO_DIR_WR		0x31UL
#define EC_CMD_PWM_FREQ_RD		0x36UL
#define EC_CMD_PWM_FREQ_WR		0x32UL
#define EC_CMD_PWM_POL_RD		0x37UL
#define EC_CMD_PWM_POL_WR		0x33UL
#define EC_CMD_SMB_FREQ_RD		0x34UL
#define EC_CMD_SMB_FREQ_WR		0x35UL
#define EC_CMD_FAN_CTL_RD		0x40UL
#define EC_CMD_FAN_CTL_WR		0x41UL
#define EC_CMD_THZ_RD			0x42UL
#define EC_CMD_DEVTBL_RD		0x20UL
#define EC_CMD_FW_INFO_RD		0xF0UL
#define EC_CMD_BUF_CLR			0xC0UL
#define EC_CMD_BUF_RD			0xC1UL
#define EC_CMD_BUF_WR			0xC2UL
#define EC_CMD_RAM_RD			0x1EUL
#define EC_CMD_RAM_WR			0x1FUL
#define EC_CMD_I2C_RW			0x0EUL
#define EC_CMD_I2C_WR			0x0FUL
#define EC_CMD_WDT_CTRL			0x28UL

/* iManager message offsets */
#define EC_MSG_OFFSET(N)		(0UL + (N))
#define EC_MSG_OFFSET_CMD		EC_MSG_OFFSET(0)
#define EC_MSG_OFFSET_STATUS		EC_MSG_OFFSET(1)
#define EC_MSG_OFFSET_PARAM		EC_MSG_OFFSET(2)
#define EC_MSG_OFFSET_DATA		EC_MSG_OFFSET(3)
#define EC_MSG_OFFSET_MEM_DATA		EC_MSG_OFFSET(4)
#define EC_MSG_OFFSET_PAYLOAD		EC_MSG_OFFSET(7)
#define EC_MSG_OFFSET_LEN		EC_MSG_OFFSET(0x2F)

/* iManager EC flags */
#define EC_IO28_OUTBUF			(BIT0)
#define EC_IO28_INBUF			(BIT1)

#define EC_F_SUCCESS			(BIT0)
#define EC_F_CMD_COMPLETE		(BIT7)
#define EC_F_HWMON_MSG			(BIT9)

//ACPI RAM Address Table
/* n = 1 ~ 2 */
#define EC_ACPIRAM_ADDR_TEMPERATURE_BASE(n)	(0x60 + 3 * ((n)-1))
#define	EC_ACPIRAM_ADDR_LOCAL_TEMPERATURE(n) 	EC_ACPIRAM_ADDR_TEMPERATURE_BASE(n)
#define	EC_ACPIRAM_ADDR_REMOTE_TEMPERATURE(n) 	(EC_ACPIRAM_ADDR_TEMPERATURE_BASE(n) + 1)
#define	EC_ACPIRAM_ADDR_WARNING_TEMPERATURE(n)	(EC_ACPIRAM_ADDR_TEMPERATURE_BASE(n) + 2)
/* N = 0 ~ 2 */
#define EC_ACPIRAM_ADDR_FAN_SPEED_BASE(N)	(0x70 + 2 * (N))
#define EC_ACPIRAM_ADDR_KERNEL_MAJOR_VERSION	0xF8
#define EC_ACPIRAM_ADDR_CHIP_VENDOR_CODE	0xFA
#define EC_ACPIRAM_ADDR_PROJECT_NAME_CODE	0xFC
#define EC_ACPIRAM_ADDR_FIRMWARE_MAJOR_VERSION	0xFE
#define EC_OFFSET_FAN_ALERT		0x6FUL
#define EC_OFFSET_FAN_ALERT_LIMIT	0x76UL
#define EC_OFFSET_BRIGHTNESS1		0x50UL
#define EC_OFFSET_BRIGHTNESS2		0x52UL
#define EC_OFFSET_BACKLIGHT_CTRL	0x99UL
#define EC_OFFSET_FW_RELEASE		0xF8UL
#define EC_OFFSET_I2C_STATUS		0UL
#define EC_RAM_ACPI 1


#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC



#define MSR_IA32_THERM_STATUS                    0x0000019C


EFI_SMM_PERIODIC_TIMER_DISPATCH_CONTEXT m_PeriodicTimerDispatch2RegCtx = { 100000, 640000, 10};/
EFI_SMM_PERIODIC_TIMER_DISPATCH_CONTEXT m_PeriodicTimerEcReadCent = {  100000,  160000, 0};
UINT64 m_PeriodicTimerCounter = 0;
UINT8 timingCounter = 0;
UINT16 timingMonitor[32];
UINT8 mHostNotiAddr = 0;
EFI_HANDLE m_TimerECioHendle = NULL;

EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL* m_PeriodicTimerDispatch = NULL;

EFI_STATUS PeriodicTimerDispatchRegister(EFI_HANDLE* DispatchHandle);
EFI_STATUS PeriodicTimerDispatchUnregister(EFI_HANDLE DispatchHandle);

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* m_TextOutput = NULL;
char* m_PendingOutput = NULL;
EFI_SMM_PCI_ROOT_BRIDGE_IO_PROTOCOL* mSmmPciRootBridgeIo = NULL;

UINT8 cpuTemp, systemTemp;
UINT8 core0Temp, core1Temp, core2Temp, core3Temp;
UINT8 smbuscount = 0;
UINT16 vin12v, vin5v, vin5vsb, vin33v, vinbat;
UINT16 fanRPM1, fanRPM2, fanRPM3;
UINT8 HmonDataBuffer[32];
UINT8 nonHNsmiCOUNT = 0;
BOOLEAN inSMBproc= FALSE;


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

typedef
VOID
(EFIAPI* EFI_AP_PROCEDURE)(
	IN OUT VOID* Buffer
	);


UINT32 StartTimeStamp = 0;
UINT32 UpdateSensorTime = 0;


UINT32 timeCheck1S = 0;
UINT32 timeCheck1E = 0;


UINT8 UpdateLoop = 0;

#define PCI_TO_PCI_ROOT_BRIDGE_IO_ADDRESS(A) \
  ((((A) << 4) & 0xff000000) | (((A) >> 4) & 0x00000700) | (((A) << 1) & 0x001f0000) | (LShiftU64((A) & 0xfff, 32)))

#define PCI_LIB_ADDRESS(Bus,Device,Function,Offset)   \
  (((Offset) & 0xfff) | (((Function) & 0x07) << 12) | (((Device) & 0x1f) << 15) | (((Bus) & 0xff) << 20))
#define PCI_ENABLE_BIT     = 0x80000000;
#define PCI_PORT_ADDRESS(bus,device,function,Offset) ( 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (Offset << 2))



/**
  MSR information returned for MSR index #MSR_IA32_THERM_STATUS
**/
typedef union {
	///
	/// Individual bit fields
	///
	struct {
		///
		/// [Bit 0] Thermal Status (RO):. If CPUID.01H:EDX[22] = 1.
		///
		UINT32  ThermalStatus : 1;
		///
		/// [Bit 1] Thermal Status Log (R/W):. If CPUID.01H:EDX[22] = 1.
		///
		UINT32  ThermalStatusLog : 1;
		///
		/// [Bit 2] PROCHOT # or FORCEPR# event (RO). If CPUID.01H:EDX[22] = 1.
		///
		UINT32  PROCHOT_FORCEPR_Event : 1;
		///
		/// [Bit 3] PROCHOT # or FORCEPR# log (R/WC0). If CPUID.01H:EDX[22] = 1.
		///
		UINT32  PROCHOT_FORCEPR_Log : 1;
		///
		/// [Bit 4] Critical Temperature Status (RO). If CPUID.01H:EDX[22] = 1.
		///
		UINT32  CriticalTempStatus : 1;
		///
		/// [Bit 5] Critical Temperature Status log (R/WC0).
		/// If CPUID.01H:EDX[22] = 1.
		///
		UINT32  CriticalTempStatusLog : 1;
		///
		/// [Bit 6] Thermal Threshold #1 Status (RO). If CPUID.01H:ECX[8] = 1.
		///
		UINT32  ThermalThreshold1Status : 1;
		///
		/// [Bit 7] Thermal Threshold #1 log (R/WC0). If CPUID.01H:ECX[8] = 1.
		///
		UINT32  ThermalThreshold1Log : 1;
		///
		/// [Bit 8] Thermal Threshold #2 Status (RO). If CPUID.01H:ECX[8] = 1.
		///
		UINT32  ThermalThreshold2Status : 1;
		///
		/// [Bit 9] Thermal Threshold #2 log (R/WC0). If CPUID.01H:ECX[8] = 1.
		///
		UINT32  ThermalThreshold2Log : 1;
		///
		/// [Bit 10] Power Limitation Status (RO). If CPUID.06H:EAX[4] = 1.
		///
		UINT32  PowerLimitStatus : 1;
		///
		/// [Bit 11] Power Limitation log (R/WC0). If CPUID.06H:EAX[4] = 1.
		///
		UINT32  PowerLimitLog : 1;
		///
		/// [Bit 12] Current Limit Status (RO). If CPUID.06H:EAX[7] = 1.
		///
		UINT32  CurrentLimitStatus : 1;
		///
		/// [Bit 13] Current Limit log (R/WC0). If CPUID.06H:EAX[7] = 1.
		///
		UINT32  CurrentLimitLog : 1;
		///
		/// [Bit 14] Cross Domain Limit Status (RO). If CPUID.06H:EAX[7] = 1.
		///
		UINT32  CrossDomainLimitStatus : 1;
		///
		/// [Bit 15] Cross Domain Limit log (R/WC0). If CPUID.06H:EAX[7] = 1.
		///
		UINT32  CrossDomainLimitLog : 1;
		///
		/// [Bits 22:16] Digital Readout (RO). If CPUID.06H:EAX[0] = 1.
		///
		UINT32  DigitalReadout : 7;
		UINT32  Reserved1 : 4;
		///
		/// [Bits 30:27] Resolution in Degrees Celsius (RO). If CPUID.06H:EAX[0] =
		/// 1.
		///
		UINT32  ResolutionInDegreesCelsius : 4;
		///
		/// [Bit 31] Reading Valid (RO). If CPUID.06H:EAX[0] = 1.
		///
		UINT32  ReadingValid : 1;
		UINT32  Reserved2 : 32;
	} Bits;
	///
	/// All bit fields as a 32-bit value
	///
	UINT32  Uint32;
	///
	/// All bit fields as a 64-bit value
	///
	UINT64  Uint64;
} MSR_IA32_THERM_STATUS_REGISTER;




//-----------------------------------------------------------------------smbus

#define R_ICH_ACPI_SMI_STS      0x34
#define B_ICH_ACPI_APM_STS      0x00000020
#define R_ICH_ACPI_SMI_EN       0x30
#define B_ICH_ACPI_EOS          0x00000002
VOID
EFIAPI
SmmCoreClearSmi (
  VOID
  )
{
  UINT16  PmBase;
  UINT32  Data32;

  IoWrite32(PCI_CONFIG_ADDRESS, PCI_PORT_ADDRESS(DEFAULT_PCI_BUS_NUMBER_PCH, PCI_DEVICE_NUMBER_PCH_SMBUS, 0, 0x10));
  Data32 = IoRead32(PCI_CONFIG_DATA);
  PmBase = (UINT16)(Data32 & 0b11111111111111111111111110000000);

  //PmBase = (UINT16) (PciRead32 (PCI_LIB_ADDRESS(LPC_BUS, LPC_DEVICE, LPC_FUNCTION, R_ACPI_PM_BASE)) & ACPI_PM_BASE_MASK);

  //
  // Clear the APM SMI Status Bit
  //
  IoWrite16 (PmBase + R_ICH_ACPI_SMI_STS, B_ICH_ACPI_APM_STS);

  //
  // Set the EOS Bit
  //
  Data32 = IoRead32 (PmBase + R_ICH_ACPI_SMI_EN);
  Data32 |= B_ICH_ACPI_EOS;
  IoWrite32 (PmBase + R_ICH_ACPI_SMI_EN, Data32);
  
  return;
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


RETURN_STATUS InternalSmBusAcquire(VOID)
{
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


RETURN_STATUS InternalSmBusStartNP(IN  UINTN IommBaseAddress, IN  UINT8   HostControl)
{
	UINT8   HostStatus;
	//
	// Set Host Control Register (Initiate Operation, Interrupt disabled).
	//
	__outbyte(SMBUS_IO_ADDRESS + SMBUS_HCTL, HostControl + SMBUS_START);

	return RETURN_SUCCESS;
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


UINTN
InternalSmBusBlock (
  IN  UINT8                     HostControl,
  IN  UINTN                     SmBusAddress,
  IN  UINT8                     *WriteBuffer,
  OUT UINT8                     *ReadBuffer,
  OUT RETURN_STATUS             *Status
  )
{
  RETURN_STATUS                 ReturnStatus;
  UINTN                         Index;
  UINTN                         BytesCount;
  UINTN                         IoPortBaseAddress;
  UINT8                         AuxiliaryControl;

  

  BytesCount = 32; 
  //
  // Try to acquire the ownership of ICH SMBUS.
  //
  ReturnStatus = InternalSmBusAcquire(); 
  if (RETURN_ERROR (ReturnStatus)) {
    goto Done;
  }

  //
  // Set the appropriate Host Control Register and auxiliary Control Register.
  //
  AuxiliaryControl = SMBUS_E32B;
  if (SMBUS_LIB_PEC(SmBusAddress)) {
    AuxiliaryControl |= B_PCH_SMBUS_AAC;
    HostControl      |= B_PCH_SMBUS_PEC_EN;
  } //나중에 확인 합니다.

  //
  // Set Host Command Register.
  //
  IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_HCMD, (UINT8) SMBUS_LIB_COMMAND (SmBusAddress));

  //
  // Set Auxiliary Control Regiester.
  //
  IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_AUXC, AuxiliaryControl);

  //
  // Clear byte pointer of 32-byte buffer.
  //
  IoRead8 (SMBUS_IO_ADDRESS + SMBUS_HCTL);

  if (WriteBuffer != NULL) {
    //
    // Write the number of block to Host Block Data Byte Register.
    //
    IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_HD0, (UINT8) BytesCount);

    //
    // Write data block to Host Block Data Register.
    //
    for (Index = 0; Index < BytesCount; Index++) {
      IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_HBD, WriteBuffer[Index]);
    }
  }

  //
  // Set SMBUS slave address for the device to send/receive from.
  //
  IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_TSA, (UINT8)SmBusAddress);


  ReturnStatus = InternalSmBusStartNP(SMBUS_IO_ADDRESS, HostControl);
  if (RETURN_ERROR (ReturnStatus)) {
    goto Done;
  }

Done:

  return BytesCount;
}



UINTN
EFIAPI
SmBusWriteBlock (
  IN  UINTN          SmBusAddress,
  OUT VOID           *Buffer,
  OUT RETURN_STATUS  *Status        OPTIONAL
  )
{
  UINTN	BytesCount = 0;
  BytesCount = InternalSmBusBlock (SMBUS_SMB_CMD_BLOCK, SmBusAddress | SMBUS_RW_SEL_WRITE, Buffer, NULL, Status );
  return BytesCount;
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

UINT8 ec_readReg8(UINTN addr, UINT8 reg) {
	__outbyte(addr, reg);
	return __inbyte(addr + 1);
}

VOID ec_writeReg8(UINTN addr, UINT8 reg, UINT8 val)
{
	__outbyte(addr, reg);
	__outbyte(addr + 1, val);
}


UINT8 ec_io18_read(UINT8 cmd)
{
	return ec_readReg8(IT8518_CMD_PORT, cmd);
}

UINT8 ec_io18_write(UINT8 cmd, UINT8 value)
{
	ec_writeReg8(IT8518_CMD_PORT, cmd, value);
	return 0;
}


INT32 imanager_check_ec_ready()
{
	int retries = 4000000;
	do {
		if (!ec_io18_read(EC_CMD_CHK_RDY))
			return 0;
	} while (--retries);

	return -1;
}


VOID ec_read_Temp_Istart(UINT8 num, BOOLEAN remote)
{
	INT8 rlen = 1;
	INT32 ret = 0;
	UINT8 offsetR = 0;
	if (remote == TRUE) offsetR = 1;	
	ec_io18_write(EC_MSG_OFFSET_LEN, rlen);
	ret = imanager_check_ec_ready();

	ec_io18_write(EC_MSG_OFFSET_PARAM, EC_RAM_ACPI); 
	ec_io18_write(EC_MSG_OFFSET_DATA, EC_ACPIRAM_ADDR_LOCAL_TEMPERATURE(num)+offsetR);
	ec_io18_write(EC_MSG_OFFSET_CMD, EC_CMD_RAM_RD);

	return;

}


INT8 ec_read_Temp_Iend(VOID)
{
	INT8 Temptemp = ec_io18_read(EC_MSG_OFFSET_MEM_DATA);
	return Temptemp;
}

INT8 ec_read_ACPItemp(UINT8 num)
{
	INT8 rlen = 1;
	INT32 ret = 0;

	ec_io18_write(EC_MSG_OFFSET_LEN, rlen);

	ret = imanager_check_ec_ready();
	if (ret)
		return -1;

	ec_io18_write(EC_MSG_OFFSET_PARAM, EC_RAM_ACPI); 
	ec_io18_write(EC_MSG_OFFSET_DATA, EC_ACPIRAM_ADDR_LOCAL_TEMPERATURE(num));
	ec_io18_write(EC_MSG_OFFSET_CMD, EC_CMD_RAM_RD); 
	ret = imanager_check_ec_ready(); 
	if (ret)
		return -1;

	ret = ec_io18_read(EC_MSG_OFFSET_STATUS); 
	if (ret != EC_F_SUCCESS)
		return -1;


	UINT8 Temptemp = 0;
	Temptemp = Temptemp + ec_io18_read(EC_MSG_OFFSET_MEM_DATA);

	return Temptemp;

}

INT8 ec_read_ACPItemp_remote(UINT8 num)
{
	INT8 rlen = 1;
	INT32 ret = 0;

	ec_io18_write(EC_MSG_OFFSET_LEN, rlen);

	ret = imanager_check_ec_ready();
	if (ret)
		return -1;

	ec_io18_write(EC_MSG_OFFSET_PARAM, EC_RAM_ACPI); 
	ec_io18_write(EC_MSG_OFFSET_DATA, EC_ACPIRAM_ADDR_REMOTE_TEMPERATURE(num)); 
	ec_io18_write(EC_MSG_OFFSET_CMD, EC_CMD_RAM_RD); 
	ret = imanager_check_ec_ready(); 
	if (ret)
		return -1;

	ret = ec_io18_read(EC_MSG_OFFSET_STATUS); 
	if (ret != EC_F_SUCCESS)
		return -1;


	UINT8 Temptemp = 0;
	Temptemp = Temptemp + ec_io18_read(EC_MSG_OFFSET_MEM_DATA);

	return Temptemp;

}


VOID ec_read_ACPIfanspeed_Istart(UINT8 num)
{
	INT8 rlen = 2;
	INT32 ret = 0;

	ec_io18_write(EC_MSG_OFFSET_LEN, rlen);

	ret = imanager_check_ec_ready();
	if (ret)
		return;

	ec_io18_write(EC_MSG_OFFSET_PARAM, EC_RAM_ACPI); 
	ec_io18_write(EC_MSG_OFFSET_DATA, EC_ACPIRAM_ADDR_FAN_SPEED_BASE(num)); 
	ec_io18_write(EC_MSG_OFFSET_CMD, EC_CMD_RAM_RD); 
}

UINT16 ec_read_ACPIfanspeed_Iend(VOID)
{
	UINT16 fanspeed = 0;
	fanspeed = ec_io18_read(EC_MSG_OFFSET_MEM_DATA);
	fanspeed = fanspeed << 8;
	fanspeed = fanspeed + ec_io18_read(EC_MSG_OFFSET_MEM_DATA + 1);

	return fanspeed;

}

INT16 ec_read_ACPIfanspeed(UINT8 num)
{
	INT8 rlen = 2;
	INT32 ret = 0;

	ec_io18_write(EC_MSG_OFFSET_LEN, rlen);

	ret = imanager_check_ec_ready();
	if (ret)
		return -1;

	ec_io18_write(EC_MSG_OFFSET_PARAM, EC_RAM_ACPI); 
	ec_io18_write(EC_MSG_OFFSET_DATA, EC_ACPIRAM_ADDR_FAN_SPEED_BASE(num)); 
	ec_io18_write(EC_MSG_OFFSET_CMD, EC_CMD_RAM_RD); 
	ret = imanager_check_ec_ready(); 
	if (ret)
		return -1;

	ret = ec_io18_read(EC_MSG_OFFSET_STATUS); 
	if (ret != EC_F_SUCCESS)
		return -1;



	UINT16 fanspeed = 0;
	fanspeed = ec_io18_read(EC_MSG_OFFSET_MEM_DATA);
	fanspeed = fanspeed << 8;
	fanspeed = fanspeed + ec_io18_read(EC_MSG_OFFSET_MEM_DATA + 1);

	return fanspeed;

}

VOID ec_read_ADC_Istart(UINT8 did)
{
	INT32 ret = 0;
	ret = imanager_check_ec_ready(); 
	if (ret)
		return;

	ec_io18_write(EC_MSG_OFFSET_PARAM, did); 
	ec_io18_write(EC_MSG_OFFSET_CMD, EC_CMD_HWP_RD);

	IoWrite8(IT8518_CMD_PORT, EC_CMD_CHK_RDY);
	return;
}

UINT16 ec_read_ADC_Iend(UINT8 scaler)
{
	UINT16 voltage = 0;
	voltage = ec_io18_read(3 + 0);
	voltage = voltage << 8;
	voltage = voltage | ec_io18_read(3 + 1);
	voltage = voltage * scaler;
	voltage = voltage * 2933 / 1000;
	return voltage;
}

INT16 ec_read_ADC(UINT8 did, UINT8 scaler)
{
	INT32 ret = 0;

	ec_io18_write(EC_MSG_OFFSET_PARAM, did); 
	ec_io18_write(EC_MSG_OFFSET_CMD, EC_CMD_HWP_RD);

	ret = imanager_check_ec_ready();  //아마도 거의 5
	if (ret)
		return -1;

	ret = ec_io18_read(EC_MSG_OFFSET_STATUS); 
	if (ret != EC_F_SUCCESS)
		return -1;



	UINT16 voltage = 0;
	voltage = ec_io18_read(3 + 0);
	voltage = voltage << 8;
	voltage = voltage | ec_io18_read(3 + 1);
	voltage = voltage * scaler;
	voltage = voltage * 2933 / 1000;
	return voltage;

}
//------------------------------------------------------------------------ec
#define MSR_SMM_FEATURE_CONTROL 0x4E0
#define MSR_IA32_TSC_AUX        0xC0000103


VOID EFIAPI ProcedureCpu0(VOID* Buffer)
{
	UINTN SmBusAddress = 0;
	RETURN_STATUS writeState;

	MSR_IA32_THERM_STATUS_REGISTER  tempMsr;
	tempMsr.Uint64 = AsmReadMsr64(MSR_IA32_THERM_STATUS);

}

VOID EFIAPI ProcedureCpu1(VOID* Buffer)
{
	RETURN_STATUS writeState;
	UINTN SmBusAddress = 0;

	MSR_IA32_THERM_STATUS_REGISTER  tempMsr;
	tempMsr.Uint64 = AsmReadMsr64(MSR_IA32_THERM_STATUS);
	core1Temp = tempMsr.Bits.DigitalReadout;

}

VOID EFIAPI ProcedureCpu2(VOID* Buffer)
{
	RETURN_STATUS writeState;
	UINTN SmBusAddress = 0;

	MSR_IA32_THERM_STATUS_REGISTER  tempMsr;
	tempMsr.Uint64 = AsmReadMsr64(MSR_IA32_THERM_STATUS);
	core2Temp = tempMsr.Bits.DigitalReadout;
}

VOID EFIAPI ProcedureCpu3(VOID* Buffer)
{
	RETURN_STATUS writeState;
	UINTN SmBusAddress = 0;

	MSR_IA32_THERM_STATUS_REGISTER  tempMsr;
	tempMsr.Uint64 = AsmReadMsr64(MSR_IA32_THERM_STATUS);
	core3Temp = tempMsr.Bits.DigitalReadout;
}


EFI_STATUS EFIAPI UpdateSensorData(EFI_HANDLE DispatchHandle, EFI_SMM_PERIODIC_TIMER_DISPATCH_CONTEXT* DispatchContext) 
{
	void* testVIOD = NULL;
	if (!ec_io18_read(EC_CMD_CHK_RDY)){
	UpdateLoop++;
	switch (UpdateLoop) {
	case 99:
		
		MSR_IA32_THERM_STATUS_REGISTER  tempMsr;
		tempMsr.Uint64 = AsmReadMsr64(MSR_IA32_THERM_STATUS);
		core0Temp = tempMsr.Bits.DigitalReadout;
		gSmst->SmmStartupThisAp(ProcedureCpu1, 1, testVIOD); 
		gSmst->SmmStartupThisAp(ProcedureCpu2, 2, testVIOD); 
		gSmst->SmmStartupThisAp(ProcedureCpu3, 3, testVIOD);
		
		ec_read_Temp_Istart(1, TRUE);
		break;
	case 1:
		cpuTemp = ec_read_Temp_Iend();

		ec_read_Temp_Istart(1, FALSE);
		break;
	case 2:
		systemTemp = ec_read_Temp_Iend();

		ec_read_ACPIfanspeed_Istart(0);
		break;
	case 3:
		fanRPM1 = ec_read_ACPIfanspeed_Iend();

		ec_read_ACPIfanspeed_Istart(1);
		break;
	case 4:
		fanRPM2 = ec_read_ACPIfanspeed_Iend();

		ec_read_ACPIfanspeed_Istart(2);
		break;
	case 5:
		fanRPM3 = ec_read_ACPIfanspeed_Iend();

		ec_read_ADC_Istart(100);
		break;

	case 6:
		vin12v = ec_read_ADC_Iend(10);

		ec_read_ADC_Istart(87);
		break;
	case 7:
		vin5v = ec_read_ADC_Iend(2);

		ec_read_ADC_Istart(90);
		break;
	case 8:
		vin5vsb = ec_read_ADC_Iend(2);

		ec_read_ADC_Istart(93);
		break;

	case 9:
		vin33v = ec_read_ADC_Iend(2);

		ec_read_ADC_Istart(81);
		break;

	case 10:
		vinbat = ec_read_ADC_Iend(2);

		HmonDataBuffer[0] = cpuTemp;
		HmonDataBuffer[1] = systemTemp;

		HmonDataBuffer[2] = (UINT8)fanRPM1;
		HmonDataBuffer[3] = (UINT8)(fanRPM1>>8);

		HmonDataBuffer[4] = (UINT8)fanRPM2;
		HmonDataBuffer[5] = (UINT8)(fanRPM2>>8);

		HmonDataBuffer[6] = (UINT8)fanRPM3;
		HmonDataBuffer[7] = (UINT8)(fanRPM3>>8);

		HmonDataBuffer[8] = (UINT8)vin12v;
		HmonDataBuffer[9] = (UINT8)(vin12v>>8);

		HmonDataBuffer[10] = (UINT8)vin5v;
		HmonDataBuffer[11] = (UINT8)(vin5v>>8);

		HmonDataBuffer[12] = (UINT8)vin5vsb;
		HmonDataBuffer[13] = (UINT8)(vin5vsb>>8);

		HmonDataBuffer[14] = (UINT8)vin33v;
		HmonDataBuffer[15] = (UINT8)(vin33v>>8);

		HmonDataBuffer[16] = (UINT8)vinbat;
		HmonDataBuffer[17] = (UINT8)(vinbat>>8);

		HmonDataBuffer[18] = core0Temp;
		HmonDataBuffer[19] = core1Temp;
		HmonDataBuffer[20] = core2Temp;
		HmonDataBuffer[21] = core3Temp;

		UINT16 PMBASE = 0;
		UINT32 Data32 = 0;
		IoWrite32(PCI_CONFIG_ADDRESS, PCI_PORT_ADDRESS(DEFAULT_PCI_BUS_NUMBER_PCH, PCI_DEVICE_NUMBER_PCH_SMBUS, 0, 0x10));
		Data32 = IoRead32(PCI_CONFIG_DATA);
		PMBASE = (UINT16)(Data32 & 0b11111111111111111111111110000000);

		UINTN SmBusAddress = 0;
		RETURN_STATUS writeState;



		SmBusAddress = SmAddrMaker(0x10, mHostNotiAddr );
		SmBusWriteBlock(SmBusAddress, HmonDataBuffer, &writeState);
		UpdateLoop = 0;
		mHostNotiAddr = 0;
		m_PeriodicTimerDispatch->UnRegister(m_PeriodicTimerDispatch, DispatchHandle);
		
		break;
	default:
		break;
	}

	}
	
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SmbusCallbackHandler(
	IN EFI_HANDLE             SmmImageHandle,
	IN OUT VOID               *CommunicationBuffer,
	IN OUT UINTN              *SourceSize
)
{

	UINTN SmBusAddress = 0;
	RETURN_STATUS writeState;

	UINT16 SmbusAddr = 0;
	UINT8 Data8 = 99;
	UINT32 Data32 = 100;	
	UINT16 PMBASE = 0;


	IoWrite32(PCI_CONFIG_ADDRESS, PCI_PORT_ADDRESS(DEFAULT_PCI_BUS_NUMBER_PCH, PCI_DEVICE_NUMBER_PCH_SMBUS, 3, 0x10));
	Data32 = IoRead32(PCI_CONFIG_DATA);
	Data32 = Data32 | 0b00000000000000000000000000000010;
	IoWrite32(PCI_CONFIG_DATA, Data32);

	Data8 = IoRead8( SMBUS_IO_ADDRESS + SMBUS_SCMD);
	Data8 = Data8 | 0b00000001;
	IoWrite8(SMBUS_IO_ADDRESS + SMBUS_SCMD, Data8);

	//---------------------------------------
	IoWrite32(PCI_CONFIG_ADDRESS, PCI_PORT_ADDRESS(DEFAULT_PCI_BUS_NUMBER_PCH, PCI_DEVICE_NUMBER_PCH_SMBUS, 0, 0x10));
	Data32 = IoRead32(PCI_CONFIG_DATA);
	PMBASE = (UINT16)(Data32 & 0b11111111111111111111111110000000);
	Data32 = IoRead32(PMBASE+0x34);
	//---------------------------------------

	Data8 = (UINT8)(Data32 >> 16);
	Data8 = Data8 & 0b00000001;
	
	if (Data8 == 1) {
		UINT32 Cbit = 0b00000000000000010000000000000000;
		IoWrite32(PMBASE + 0x34, Cbit);

		UINT8 SlaveSTS = IoRead8( SMBUS_IO_ADDRESS + SMBUS_SSTS);
		if (SlaveSTS == 1) {

			UINT8 HostNotiAddr = IoRead8( SMBUS_IO_ADDRESS + SMBUS_NDA);
			UINT8 HostNotiH = IoRead8( SMBUS_IO_ADDRESS + SMBUS_NDHB);
			UINT8 HostNotiL = IoRead8( SMBUS_IO_ADDRESS + SMBUS_NDLB);
			HostNotiAddr = HostNotiAddr >> 1;
			IoWrite8(SMBUS_IO_ADDRESS + SMBUS_SSTS, 0x1);
		           

		
			switch (HostNotiH)
			{
			case 0xAC:

					if (m_PeriodicTimerDispatch)
					{
						mHostNotiAddr = HostNotiAddr;
						EFI_STATUS XST = m_PeriodicTimerDispatch->Register(m_PeriodicTimerDispatch, UpdateSensorData, &m_PeriodicTimerEcReadCent, &m_TimerECioHendle);

						
						MSR_IA32_THERM_STATUS_REGISTER  tempMsr;
						tempMsr.Uint64 = AsmReadMsr64(MSR_IA32_THERM_STATUS);
						core0Temp = tempMsr.Bits.DigitalReadout;
						void* testVIOD = NULL;
						gSmst->SmmStartupThisAp(ProcedureCpu1, 1, testVIOD); //tet
						gSmst->SmmStartupThisAp(ProcedureCpu2, 2, testVIOD); //tet
						gSmst->SmmStartupThisAp(ProcedureCpu3, 3, testVIOD);

						ec_read_Temp_Istart(1, TRUE);
					}

					IoWrite32(PCI_CONFIG_ADDRESS, PCI_PORT_ADDRESS(DEFAULT_PCI_BUS_NUMBER_PCH, PCI_DEVICE_NUMBER_PCH_SMBUS, 6, 0x0));
					Data32 = IoRead32(PCI_CONFIG_DATA);

					break;
			default:
			   SmBusAddress = SmAddrMaker(0xAA, HostNotiAddr );
			   SmBusWriteDataByte(SmBusAddress, nonHNsmiCOUNT , &writeState);
			   SmBusAddress = SmAddrMaker(0xAB, HostNotiAddr );
			   SmBusWriteDataByte(SmBusAddress, HostNotiAddr , &writeState);
			   SmBusAddress = SmAddrMaker(0xAC, HostNotiAddr );
			   SmBusWriteDataByte(SmBusAddress, HostNotiH , &writeState);
			   SmBusAddress = SmAddrMaker(0xAD, HostNotiAddr );
			   SmBusWriteDataByte(SmBusAddress, HostNotiL , &writeState);
				break;
			}

		}else {
			nonHNsmiCOUNT++;
			UINT8   HostStatus;
			HostStatus = __inbyte(SMBUS_IO_ADDRESS + SMBUS_HSTS);
			if ((HostStatus & (SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD)) == 0) {
				IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_HSTS, B_PCH_SMBUS_HSTS_ALL);
			    IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_AUXS, B_PCH_SMBUS_CRCE);
			}
			else {
				__outbyte(SMBUS_IO_ADDRESS + SMBUS_HSTS, (SMBUS_DERR | SMBUS_BERR | SMBUS_BYTE_FAILD));
				IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_HSTS, B_PCH_SMBUS_HSTS_ALL);
			    IoWrite8 (SMBUS_IO_ADDRESS + SMBUS_AUXS, B_PCH_SMBUS_CRCE);
			}
		}
		SmmCoreClearSmi();
	}
	   	 
	return EFI_SUCCESS;
}


EFI_STATUS EFIAPI PeriodicTimerDispatchProtocolNotifyHandler(EFI_EVENT Event, PVOID Context)
{
	EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL* PeriodicTimerDispatch = NULL;
	gBS->LocateProtocol(&gEfiSmmPeriodicTimerDispatchProtocolGuid, NULL, &PeriodicTimerDispatch);
	m_PeriodicTimerDispatch = PeriodicTimerDispatch;
	return EFI_SUCCESS;
}

EFI_STATUS RegisterProtocolNotifyDxe( 
	EFI_GUID* Guid, EFI_EVENT_NOTIFY Handler,
	EFI_EVENT* Event, PVOID* Registration)
{
	EFI_STATUS Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, Handler, NULL, Event); 
	if (EFI_ERROR(Status))
	{
		return Status;
	}
	Status = gBS->RegisterProtocolNotify(Guid, *Event, (PVOID)Registration);
	if (EFI_ERROR(Status))
	{
		return Status;
	}
	return Status;
}


EFI_STATUS
HmonEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable) {	
	gST = SystemTable;
	gBS = gST->BootServices;
	EFI_STATUS Status = EFI_SUCCESS;
	BOOLEAN bInSmram = FALSE;
	EFI_SMM_BASE2_PROTOCOL* SmmBase2 = NULL;

	Status = gBS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, NULL, &SmmBase2);
	if (Status == EFI_SUCCESS) {
		SmmBase2->InSmm(SmmBase2, &bInSmram);
	}else{
		
	}
		if (bInSmram) {
		Status = SmmBase2->GetSmstLocation(SmmBase2, &gSmst);
		if (Status == EFI_SUCCESS){
			EFI_SMM_BASE_PROTOCOL* SmmBase1 = NULL; 
			gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase1); 
			
			
			
			PVOID Registration = NULL;
			EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL* PeriodicTimerDispatch = NULL;
			Status = gBS->LocateProtocol(&gEfiSmmPeriodicTimerDispatchProtocolGuid, NULL, &PeriodicTimerDispatch);
			if (Status == EFI_SUCCESS)	{
				m_PeriodicTimerDispatch = PeriodicTimerDispatch;
			}
			else
			{
				EFI_EVENT Event = NULL;
		


				RegisterProtocolNotifyDxe(&gEfiSmmPeriodicTimerDispatchProtocolGuid, PeriodicTimerDispatchProtocolNotifyHandler, &Event, &Registration);
			}

			
			
			SmmBase1->RegisterCallback(SmmBase1, ImageHandle, SmbusCallbackHandler, FALSE, FALSE); //alpha
			
		}
	}
	else {
	}
	return EFI_SUCCESS;
}


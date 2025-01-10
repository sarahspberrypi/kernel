use core::arch::asm;
use core::ptr;
use hermit_sync::InterruptSpinMutex;
use x86_64::instructions::hlt;
use x86_64::registers::model_specific::Msr;
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::page::Size2MiB;

use crate::scheduler;
use crate::arch::mm::virtualmem::allocate_aligned;
use crate::arch::mm::paging::map_sev;



// The GHCB MSR
#[derive(Debug)]
pub struct GhcbMsr;

impl GhcbMsr {
    // The VM can read and write the GHCB value through this specific register
    // See AMD SEV-ES Guest Hypervisor Communcation Block Standardization for further information.
    pub const MSR: Msr = Msr::new(0xc001_0130); 

    pub const EXIT_REQUEST: u64 = 0x100;

    const GUEST_PHYS_ADDR: u64 = 0x000;
    const SEV_INFORMATION: u64 = 0x001;
    const SEV_INFORMATION_REQUEST: u64 = 0x002;
    const CPUID_REQUEST: u64 = 0x004;
    const CPUID_RESPONSE: u64 = 0x005;
    const PREFERRED_GUEST_PHYS_ADDR_REQUEST: u64 = 0x010;
    const PREFFERED_GUEST_PHYS_ADDR_RESPONSE: u64 = 0x011;
    const GUEST_PHYS_ADDR_REQUEST: u64 = 0x012;
    const GUEST_PHYS_ADDR_RESPONSE: u64 = 0x013;
    const PAGE_STATE_CHANGE_REQUEST: u64 = 0x014;
    const PAGE_STATE_CHANGE_RESPONSE: u64 = 0x015;

    const PAGE_STATE_CHANGE_POS: u64 = 52; // this bit can be set to 1 (private) or 2 (shared)

}

// GHCB Layout according to AMD SEV-ES Guest Hypervisor Communcation Block Standardization
#[derive(Debug, Copy, Clone)]
#[repr(C, align(4096))]
pub struct Ghcb {
    reserved1: [u8; 0xcb],
    cpl: u8,
    reserved2: [u8; 0x74],
    xss: u64,
    reserved3: [u8; 0x18],
    dr7: u64,
    reserved4: [u8; 0x90],
    rax: u64,
    reserved5: [u8; 0x108],
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved6: [u8; 0x70],
    sw_exitcode: u64,
    sw_exitinfo1: u64,
    sw_exitinfo2: u64,
    sw_scratch: u64,
    reserved7: [u8; 0x38],
    xcr0: u64,
    valid_bitmap: [u8; 0x10],
    x87_state_gpa: u64,
    reserved8: [u8; 0x3f8],
    shared_buffer: [u8; 0x7f0],
    reserved9: [u8; 0xa],
    protocol_version: u16,
    ghcb_usage: u32,
}

pub(crate) static GHCB: InterruptSpinMutex<Option<&mut Ghcb>> = InterruptSpinMutex::new(None); 


impl Ghcb {
    #[inline]
    pub const fn new() -> Self {
            Self {
                reserved1: [0; 203],
                cpl: 0,
                reserved2: [0; 116],
                xss: 0,
                reserved3: [0; 24],
                dr7: 0,
                reserved4: [0; 144],
                rax: 0,
                reserved5: [0; 264],
                rcx: 0,
                rdx: 0,
                rbx: 0,
                reserved6: [0; 112],
                sw_exitcode: 0,
                sw_exitinfo1: 0,
                sw_exitinfo2: 0,
                sw_scratch: 0,
                reserved7: [0; 56],
                xcr0: 0,
                valid_bitmap: [0; 16],
                x87_state_gpa: 0,
                reserved8: [0; 1016],
                shared_buffer: [0; 2032],
                reserved9: [0; 10],
                protocol_version: 0,
                ghcb_usage: 0,
            }
    }

}

// This function performs an exit to the hypervisor 
#[inline(always)]
pub unsafe fn vmgexit_msr(request_code: u64, data: u64, response: u64) -> u64 {

    let val = request_code | data;

    let mut msr = GhcbMsr::MSR;
    msr.write(val);
    asm!("rep vmmcall", options(nostack));
    let retcode = msr.read();

    if retcode != response {
        panic!("The returnvalue from the hypervisor {retcode:} does not match the expected value {response:}");
    }

    retcode
}

// This function reads the address stored in the MSR which points to the GHCB and prints the address and the GHCB to the console.
pub unsafe fn read_msr() {
    let mut msr = GhcbMsr::MSR;
    let ret = msr.read();
    debug!("msr is {ret:#x}");
    let addr:*mut Ghcb = VirtAddr::new(ret).as_mut_ptr();
    debug!("ghcb is {:x?}", *addr);
}

// Sends a termination request to the MSR
pub fn terminate() {
    unsafe {
        vmgexit_msr(GhcbMsr::EXIT_REQUEST, 0x0, 0);
    }
    hlt();
}

// This function reads the address of the GHCB from the MSR and stores it inside a Mutex
pub unsafe fn init() {
    let mut msr = GhcbMsr::MSR;

    let mut ghcb = GHCB.lock();
    let ghcb_ref = VirtAddr::new(msr.read()).as_mut_ptr::<Ghcb>().as_mut();

    *ghcb = ghcb_ref;   
        
}
    

pub fn make_page_shared(addr: x86_64::VirtAddr) {
    //TODO: validate page beforehand
    debug!("making page shared");
    if map_sev::<Size2MiB>(addr).is_err() {
        panic_println!("Cannot make page shared!");
        scheduler::abort();
    }

    const SHARED: u64 = 2 << GhcbMsr::PAGE_STATE_CHANGE_POS; //mark page as shared

    let value = addr.as_u64() | SHARED;
    debug!("writing to msr");

    unsafe {
        let ret = vmgexit_msr(GhcbMsr::PAGE_STATE_CHANGE_REQUEST, value, GhcbMsr::PAGE_STATE_CHANGE_RESPONSE);
    }
}

pub fn make_page_private(addr: VirtAddr) {
    //TODO: validate page beforehand

    if map_sev::<Size2MiB>(addr).is_err() {
        panic_println!("Cannot make page shared!");
        scheduler::abort();
    }

    const PRIVATE: u64 = 1 << GhcbMsr::PAGE_STATE_CHANGE_POS; //mark page as private

    let value = addr.as_u64() | PRIVATE;

    unsafe {
        let ret = vmgexit_msr(GhcbMsr::PAGE_STATE_CHANGE_REQUEST, value, GhcbMsr::PAGE_STATE_CHANGE_RESPONSE);
    }
}
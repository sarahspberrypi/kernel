use core::arch::asm;
use alloc::alloc::Allocator;
use memory_addresses::MemoryAddress;
use x86_64::VirtAddr;

use crate::arch::kernel::ghcb;
use crate::arch::mm::physicalmem;
use crate::arch::mm::virtualmem;
use crate::mm::device_alloc;


// See SEV-SNP ABI Specification 7.3 Attestation
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub struct SNPMessageReportRequest {
    pub report_data: [u8; 64], // Guest-provided data to be included in the attestation report.
    pub vmpl: u32, // The VMPL to put in the attestation report. Must be greater than or equal to the current VMPL and, at most, three. Will probably always be 0.
    pub key_sel: u32, // Selects which key to use for generating the signature. Must be either 0, 1 or 2.
    reserved: [u8; 24], // Reserved, must be 0.
}

impl SNPMessageReportRequest {
    pub fn new(report_data: [u8;64]) -> Self {
        Self {
            report_data: report_data,
            vmpl: 0,
            key_sel: 0,
            reserved: [0; 24],
        }
    }
}

#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub struct SNPMessageReportResponse {
    pub status: Status,
    pub report_size: u32,
    reserved: [u8; 24],
    pub report: AttestationReport,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Status {
    Success = 0,
    InvalidParameters = 0x16,
    InvalidKeySelection = 0x27,
}

#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub struct AttestationReport {
    version: u32,
    guest_svn: u32,
    policy: u64,
    family_id: u128,
    image_id: u128,
    vmpl: u32,
    signature_algo: u32,
    current_tcb: u64,
    platform_info: u64,
    keys: u32, 
    reserved0: u32,
    report_data: [u8; 64], // If requested by guest, the report_data from SNPMessageReportRequest will be here
    measurement: [u8; 48],
    host_data: [u8; 32],
    id_key_digest: [u8; 48],
    author_key_digest: [u8; 48],
    report_id: [u8; 32],
    report_id_ma: [u8; 32],
    reported_tcb: u64,
    cpuid_fam_id: u8,
    cpuid_mod_id: u8,
    cpuid_step: u8,
    reserved1: [u8; 20],
    chip_id: [u8; 64],
    committed_tcb: u64,
    current_build: u8,
    current_minor: u8,
    current_major: u8,
    reserved2: u8,
    committed_build: u8,
    committed_minor: u8,
    committed_major: u8,
    reserved3: u8,
    launch_tcb: u64,
    reserved4: [u8; 168],
    signature: [u8; 512],
}

#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub enum SNPMessageReport {
    Request (SNPMessageReportRequest),
    Response (SNPMessageReportResponse),
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub struct SNPMessageHeader {
    authtag: [u8; 32],
    msg_seqno: u64,
    reserved0: u64,
    algo: u8,
    hdr_version: u8,
    hdr_size: u16,
    msg_type: u8,
    msg_version: u8,
    msg_size: u16,
    reserved1: u32,
    msg_vmpck: u8,
    reserved2: [u8; 7],
    payload: SNPMessageReport,
}

const HEADERSIZE: u16 = size_of::<SNPMessageHeader>() as u16;

impl SNPMessageHeader {
    pub fn new(msg_size: u16, msg_type: u8, msg_seqno: u64, payload: SNPMessageReport) -> Self {
        Self {
            authtag: [0; 32],
            msg_seqno: msg_seqno,
            reserved0: 0,
            algo: 1,
            hdr_version: 0x1,
            hdr_size: HEADERSIZE,
            msg_type: msg_type, // 5 for MSG_REPORT_REQ, 6 for MSG_REPORT_RSP
            msg_version: 1,
            msg_size: msg_size,
            reserved1: 0,
            msg_vmpck: 0, // If VLEK is installed, sign with VLEK. Otherwise, sign with VCEK
            reserved2: [0; 7],
            payload: payload,
        }
    }
}

pub fn request_attestation() {
    panic_println!("requesting attestation from PSP");
    let gpa_req = virtualmem::allocate_aligned(0x1000, 0x1000).unwrap();
    let gpa_resp = virtualmem::allocate_aligned(0x1000, 0x1000).unwrap();
    // let allocator = device_alloc::DeviceAlloc;
    // let layout= core::alloc::Layout::from_size_align(0x1000, 0x1000).unwrap();
    // let gpa_req = allocator.allocate(layout).unwrap();
    // let gpa_resp = allocator.allocate(layout).unwrap();

    unsafe{
        let pt = crate::arch::mm::paging::identity_mapped_page_table();
        debug!("request gpa");
        crate::arch::mm::paging::disect(pt, VirtAddr::new(gpa_req.as_usize() as u64));
        let pt = crate::arch::mm::paging::identity_mapped_page_table();
        debug!("response gpa");
        crate::arch::mm::paging::disect(pt, VirtAddr::new(gpa_resp.as_usize() as u64));
    }
    debug!("making pages shared");
    ghcb::make_page_shared(VirtAddr::new(gpa_req.as_usize() as u64));
    ghcb::make_page_shared(VirtAddr::new(gpa_resp.as_usize() as u64));
    debug!("success");
    let report_data: [u8; 64] = [
        137, 42, 219, 83, 201, 55, 112, 6, 
        245, 18, 94, 167, 33, 210, 76, 149, 
        22, 188, 61, 134, 7, 252, 99, 173, 
        46, 118, 231, 14, 87, 205, 160, 39, 
        102, 69, 216, 3, 145, 28, 191, 57, 
        234, 11, 180, 95, 128, 62, 247, 16, 
        89, 203, 36, 171, 5, 238, 124, 67, 
        152, 20, 196, 73, 109, 254, 41, 214
    ];   
    debug!("report data: {report_data:?}");
    let request: SNPMessageReportRequest = SNPMessageReportRequest::new(report_data);
    let gpa_req_ptr: *mut SNPMessageReportRequest = gpa_req.as_usize() as *mut SNPMessageReportRequest; //FIXME: unsound shit
    unsafe {core::ptr::write(gpa_req_ptr, request);}
    debug!("Attestation request posted at physical address {gpa_req:x}, response will be available at physical address {gpa_resp:x}.");
    unsafe {ghcb::vmgexit(0x8000_0011, gpa_req.as_usize() as u64, gpa_resp.as_usize() as u64);}

    let answer: SNPMessageReportResponse = unsafe {core::ptr::read(gpa_resp.as_usize() as *const _)};
    // let measurement = match answer.payload {
    //     SNPMessageReport::Response(response) => {
    //         response.report.measurement
    //     },
    //     _ => panic!("Request was not handled properly")
    // };
    let measurement = answer.report.measurement;
    debug!("measurement is {measurement:?}");
}
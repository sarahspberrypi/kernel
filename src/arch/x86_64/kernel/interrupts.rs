use alloc::collections::BTreeMap;
use x86_64::instructions::interrupts;
use x86_64::instructions::tables::sidt;
use x86_64::structures::DescriptorTablePointer;
use core::arch::asm;
use core::slice;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use ahash::RandomState;
use hashbrown::HashMap;
use hermit_sync::{InterruptSpinMutex, InterruptTicketMutex, OnceCell};
#[cfg(not(feature = "idle-poll"))]
use x86_64::instructions::interrupts::enable_and_hlt;
pub use x86_64::instructions::interrupts::{disable, enable};
use x86_64::set_general_handler;
use x86_64::structures::idt::InterruptDescriptorTable;
pub use x86_64::structures::idt::InterruptStackFrame as ExceptionStackFrame;

use crate::arch::x86_64::kernel::ghcb;
use crate::arch::x86_64::kernel::core_local::{core_scheduler, increment_irq_counter};
use crate::arch::x86_64::kernel::{apic, processor};
use crate::arch::x86_64::mm::paging::{page_fault_handler, BasePageSize, PageSize};
use crate::arch::x86_64::swapgs;
#[cfg(not(feature = "pci"))]
use crate::drivers::mmio::get_interrupt_handlers;
#[cfg(feature = "pci")]
use crate::drivers::pci::get_interrupt_handlers;
use crate::drivers::InterruptHandlerQueue;
use crate::scheduler::{self, CoreId};

static IRQ_HANDLERS: OnceCell<HashMap<u8, InterruptHandlerQueue, RandomState>> = OnceCell::new();
static IRQ_NAMES: InterruptTicketMutex<HashMap<u8, &'static str, RandomState>> =
	InterruptTicketMutex::new(HashMap::with_hasher(RandomState::with_seeds(0, 0, 0, 0)));

pub(crate) const IST_ENTRIES: usize = 4;
pub(crate) const IST_SIZE: usize = 8 * BasePageSize::SIZE as usize;

pub(crate) static IDT: InterruptSpinMutex<InterruptDescriptorTable> =
	InterruptSpinMutex::new(InterruptDescriptorTable::new());

pub(crate) fn load_idt() {
	// FIXME: This is not sound! For this to be sound, the table must never be
	// modified or destroyed while in use. This is _not_ the case here. Instead, we
	// disable interrupts on the current core when modifying the table and hope for
	// the best in regards to interrupts on other cores.
	
	x86_64::instructions::interrupts::disable();
	let enabled = interrupts::are_enabled();
	debug!("are interrupts enabled? {enabled:}");

	unsafe {
		let current_idt = sidt();
		let current_idt_entry: *const u64 = current_idt.base.as_ptr();
		let base: InterruptDescriptorTable = core::ptr::read_unaligned(current_idt.base.as_ptr());
		// debug!("base at {:#x?}, entry at {current_idt_entry:x?}", base);
		// let bytes = slice::from_raw_parts(current_idt_entry, 32);
		let cur_idt= current_idt.base.as_mut_ptr::<InterruptDescriptorTable>();
		
		
		let uefi_ir29 = (*cur_idt).vmm_communication_exception.handler_addr();
		debug!("uefi ir 29 is {uefi_ir29:#x?}");
		debug!("setting handler");
		let mut idt = IDT.lock();

		set_general_handler!(&mut *idt, abort, 0..29);
		set_general_handler!(&mut *idt, abort, 30..32);
		set_general_handler!(&mut *idt, handle_interrupt, 32..);

		for i in 32..=255 {
			let addr = idt[i].handler_addr();
			idt[i].set_handler_addr(addr).set_stack_index(0);
		}
		// idt.vmm_communication_exception.set_handler_addr(uefi_ir29).set_stack_index(0);
		idt.vmm_communication_exception.set_handler_fn(vmm_communication_exception).set_stack_index(0);
		idt.divide_error
			.set_handler_fn(divide_error_exception)
			.set_stack_index(0);
		idt.debug.set_handler_fn(debug_exception).set_stack_index(0);
		idt.breakpoint
			.set_handler_fn(breakpoint_exception)
			.set_stack_index(0);
		idt.overflow
			.set_handler_fn(overflow_exception)
			.set_stack_index(0);
		idt.bound_range_exceeded
			.set_handler_fn(bound_range_exceeded_exception)
			.set_stack_index(0);
		idt.invalid_opcode
			.set_handler_fn(invalid_opcode_exception)
			.set_stack_index(0);
		idt.device_not_available
			.set_handler_fn(device_not_available_exception)
			.set_stack_index(0);
		idt.invalid_tss
			.set_handler_fn(invalid_tss_exception)
			.set_stack_index(0);
		idt.segment_not_present
			.set_handler_fn(segment_not_present_exception)
			.set_stack_index(0);
		idt.stack_segment_fault
			.set_handler_fn(stack_segment_fault_exception)
			.set_stack_index(0);
		idt.general_protection_fault
			.set_handler_fn(general_protection_exception)
			.set_stack_index(0);
		idt.page_fault
			.set_handler_fn(page_fault_handler)
			.set_stack_index(0);
		idt.x87_floating_point
			.set_handler_fn(floating_point_exception)
			.set_stack_index(0);
		idt.alignment_check
			.set_handler_fn(alignment_check_exception)
			.set_stack_index(0);
		idt.simd_floating_point
			.set_handler_fn(simd_floating_point_exception)
			.set_stack_index(0);
		idt.virtualization
			.set_handler_fn(virtualization_exception)
			.set_stack_index(0);
		idt.double_fault
			.set_handler_fn(double_fault_exception)
			.set_stack_index(1);
		idt.non_maskable_interrupt
			.set_handler_fn(nmi_exception)
			.set_stack_index(2);
		idt.machine_check
			.set_handler_fn(machine_check_exception)
			.set_stack_index(3);
		idt.device_not_available
			.set_handler_fn(device_not_available_exception)
			.set_stack_index(0);
		idt.reserved_1
			.set_handler_fn(debug_exception)
			.set_stack_index(0);
		for i in 0..6 {
			idt.reserved_2[i]
				.set_handler_fn(debug_exception)
				.set_stack_index(0);
		}
		idt.reserved_3
			.set_handler_fn(debug_exception)
			.set_stack_index(0);
		
		(*IDT.data_ptr()).load_unsafe();
	}
}

#[inline]
pub(crate) fn enable_and_wait() {
	#[cfg(feature = "idle-poll")]
	unsafe {
		asm!("pause", options(nomem, nostack, preserves_flags));
	}

	#[cfg(not(feature = "idle-poll"))]
	if crate::processor::supports_mwait() {
		let addr = ptr::from_ref(core_scheduler().get_priority_bitmap()).cast::<u8>();

		unsafe {
			if crate::processor::supports_clflush() {
				core::arch::x86_64::_mm_clflush(addr);
			}

			asm!(
				"monitor",
				in("rax") addr,
				in("rcx") 0,
				in("rdx") 0,
				options(readonly, nostack, preserves_flags)
			);

			// The maximum waiting time is an implicit 64-bit timestamp-counter value
			// stored in the EDX:EBX register pair.
			// Test timeout by changing "b" => (0xffffffff) or "d"((wakeup >> 32) + 1)
			// ECX bit 31 indicate whether timeout feature is used
			// EAX [0:3] indicate sub C-state; [4:7] indicate C-states e.g., 0=>C1, 1=>C2 ...
			asm!(
				"sti; mwait",
				in("rax") 0x2,
				in("rcx") 0 /* break on interrupt flag */,
				options(readonly, nostack, preserves_flags)
			);
		}
	} else {
		#[cfg(feature = "smp")]
		crate::CoreLocal::get().hlt.store(true, Ordering::Relaxed);
		enable_and_hlt();
	}
}

pub(crate) fn install() {
	let mut idt = IDT.lock();

	set_general_handler!(&mut *idt, abort, 0..32);
	set_general_handler!(&mut *idt, handle_interrupt, 32..);

	unsafe {
		for i in 32..=255 {
			let addr = idt[i].handler_addr();
			idt[i].set_handler_addr(addr).set_stack_index(0);
		}

		idt.divide_error
			.set_handler_fn(divide_error_exception)
			.set_stack_index(0);
		idt.debug.set_handler_fn(debug_exception).set_stack_index(0);
		idt.breakpoint
			.set_handler_fn(breakpoint_exception)
			.set_stack_index(0);
		idt.overflow
			.set_handler_fn(overflow_exception)
			.set_stack_index(0);
		idt.bound_range_exceeded
			.set_handler_fn(bound_range_exceeded_exception)
			.set_stack_index(0);
		idt.invalid_opcode
			.set_handler_fn(invalid_opcode_exception)
			.set_stack_index(0);
		idt.device_not_available
			.set_handler_fn(device_not_available_exception)
			.set_stack_index(0);
		idt.invalid_tss
			.set_handler_fn(invalid_tss_exception)
			.set_stack_index(0);
		idt.segment_not_present
			.set_handler_fn(segment_not_present_exception)
			.set_stack_index(0);
		idt.stack_segment_fault
			.set_handler_fn(stack_segment_fault_exception)
			.set_stack_index(0);
		idt.general_protection_fault
			.set_handler_fn(general_protection_exception)
			.set_stack_index(0);
		idt.page_fault
			.set_handler_fn(page_fault_handler)
			.set_stack_index(0);
		idt.x87_floating_point
			.set_handler_fn(floating_point_exception)
			.set_stack_index(0);
		idt.alignment_check
			.set_handler_fn(alignment_check_exception)
			.set_stack_index(0);
		idt.simd_floating_point
			.set_handler_fn(simd_floating_point_exception)
			.set_stack_index(0);
		idt.virtualization
			.set_handler_fn(virtualization_exception)
			.set_stack_index(0);
		idt.double_fault
			.set_handler_fn(double_fault_exception)
			.set_stack_index(1);
		idt.non_maskable_interrupt
			.set_handler_fn(nmi_exception)
			.set_stack_index(2);
		idt.machine_check
			.set_handler_fn(machine_check_exception)
			.set_stack_index(3);
		idt.device_not_available
			.set_handler_fn(device_not_available_exception)
			.set_stack_index(0);
	}

	IRQ_NAMES.lock().insert(7, "FPU");
}

pub(crate) fn install_handlers() {
	IRQ_HANDLERS.set(get_interrupt_handlers()).unwrap();
}

fn handle_interrupt(stack_frame: ExceptionStackFrame, index: u8, _error_code: Option<u64>) {
	debug!("received interrupt {index}");

	crate::arch::x86_64::swapgs(&stack_frame);
	use crate::arch::kernel::core_local::core_scheduler;
	use crate::scheduler::PerCoreSchedulerExt;

	if let Some(handlers) = IRQ_HANDLERS.get() {
		if let Some(map) = handlers.get(&(index - 32)) {
			for handler in map.iter() {
				handler();
			}
		}
	}

	apic::eoi();
	increment_irq_counter(index);

	crate::executor::run();

	core_scheduler().reschedule();
	crate::arch::x86_64::swapgs(&stack_frame);
}

fn abort(stack_frame: ExceptionStackFrame, index: u8, error_code: Option<u64>) {
	panic_println!("Exception {index}");
	panic_println!("Error code: {error_code:?}");
	panic_println!("Stack frame: {stack_frame:#?}");
	scheduler::abort();
}

extern "x86-interrupt" fn divide_error_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Divide Error (#DE) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn debug_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Debug (#DB) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn nmi_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Non-Maskable Interrupt (NMI) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn breakpoint_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Breakpoint (#BP) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn overflow_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Overflow (#OF) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn bound_range_exceeded_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("BOUND Range Exceeded (#BR) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn invalid_opcode_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Invalid Opcode (#UD) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn device_not_available_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	// We set the CR0_TASK_SWITCHED flag every time we switch to a task.
	// This causes the "Device Not Available" Exception (int #7) to be thrown as soon as we use the FPU for the first time.

	increment_irq_counter(7);

	// Clear CR0_TASK_SWITCHED so this doesn't happen again before the next switch.
	unsafe {
		asm!("clts", options(nomem, nostack));
	}

	// Let the scheduler set up the FPU for the current task.
	core_scheduler().fpu_switch();
	swapgs(&stack_frame);
}

extern "x86-interrupt" fn invalid_tss_exception(stack_frame: ExceptionStackFrame, _code: u64) {
	swapgs(&stack_frame);
	panic_println!("Invalid TSS (#TS) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn segment_not_present_exception(
	stack_frame: ExceptionStackFrame,
	_code: u64,
) {
	swapgs(&stack_frame);
	panic_println!("Segment Not Present (#NP) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn stack_segment_fault_exception(
	stack_frame: ExceptionStackFrame,
	error_code: u64,
) {
	swapgs(&stack_frame);
	panic_println!(
		"Stack Segment Fault (#SS) Exception: {:#?}, error {:#X}",
		stack_frame, error_code
	);
	scheduler::abort();
}

extern "x86-interrupt" fn general_protection_exception(
	stack_frame: ExceptionStackFrame,
	error_code: u64,
) {
	swapgs(&stack_frame);
	panic_println!(
		"General Protection (#GP) Exception: {:#?}, error {:#X}",
		stack_frame, error_code
	);
	panic_println!(
		"fs = {:#X}, gs = {:#X}",
		processor::readfs(),
		processor::readgs()
	);
	scheduler::abort();
}

extern "x86-interrupt" fn double_fault_exception(
	stack_frame: ExceptionStackFrame,
	error_code: u64,
) -> ! {
	swapgs(&stack_frame);
	panic_println!(
		"Double Fault (#DF) Exception: {:#?}, error {:#X}",
		stack_frame, error_code
	);
	scheduler::abort()
}

extern "x86-interrupt" fn floating_point_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Floating-Point Error (#MF) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn alignment_check_exception(stack_frame: ExceptionStackFrame, _code: u64) {
	swapgs(&stack_frame);
	panic_println!("Alignment Check (#AC) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn machine_check_exception(stack_frame: ExceptionStackFrame) -> ! {
	swapgs(&stack_frame);
	panic_println!("Machine Check (#MC) Exception: {:#?}", stack_frame);
	scheduler::abort()
}

extern "x86-interrupt" fn simd_floating_point_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("SIMD Floating-Point (#XM) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn virtualization_exception(stack_frame: ExceptionStackFrame) {
	swapgs(&stack_frame);
	panic_println!("Virtualization (#VE) Exception: {:#?}", stack_frame);
	scheduler::abort();
}

extern "x86-interrupt" fn vmm_communication_exception(stack_frame: ExceptionStackFrame, code: u64) {
	swapgs(&stack_frame);
	match code {
		0x7b => {
			let addr = (*stack_frame).instruction_pointer;
			ghcb::make_page_shared(addr);
			unsafe {
				ghcb::vmgexit_msr(0x403, code, 0);//TODO: what response?
				// *stack_frame.instruction_pointer.as_mut_ptr::<u64>().as_mut().unwrap() += 2u64 // jump to next instruction, replace with assembly code
			} 
		},
		_ => {
			panic_println!("Unhandled #VC error {code:#x}");
			scheduler::abort();
		},
	}
	
}

pub(crate) fn add_irq_name(irq_number: u8, name: &'static str) {
	debug!("Register name \"{}\"  for interrupt {}", name, irq_number);
	IRQ_NAMES.lock().insert(32 + irq_number, name);
}

fn get_irq_name(irq_number: u8) -> Option<&'static str> {
	IRQ_NAMES.lock().get(&irq_number).copied()
}

pub(crate) static IRQ_COUNTERS: InterruptSpinMutex<BTreeMap<CoreId, &IrqStatistics>> =
	InterruptSpinMutex::new(BTreeMap::new());

pub(crate) struct IrqStatistics {
	pub counters: [AtomicU64; 256],
}

impl IrqStatistics {
	pub const fn new() -> Self {
		#[allow(clippy::declare_interior_mutable_const)]
		const NEW_COUNTER: AtomicU64 = AtomicU64::new(0);
		IrqStatistics {
			counters: [NEW_COUNTER; 256],
		}
	}

	pub fn inc(&self, pos: u8) {
		self.counters[usize::from(pos)].fetch_add(1, Ordering::Relaxed);
	}
}

pub(crate) fn print_statistics() {
	panic_println!("Number of interrupts");
	for (core_id, irg_statistics) in IRQ_COUNTERS.lock().iter() {
		for (i, counter) in irg_statistics.counters.iter().enumerate() {
			let counter = counter.load(Ordering::Relaxed);
			if counter > 0 {
				match get_irq_name(i.try_into().unwrap()) {
					Some(name) => {
						panic_println!("[{core_id}][{name}]: {counter}");
					}
					_ => {
						panic_println!("[{core_id}][{i}]: {counter}");
					}
				}
			}
		}
	}
}

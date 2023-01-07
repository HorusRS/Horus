use bcc::perf_event::PerfMapBuilder;
use bcc::BccError;
use bcc::{Kprobe, Kretprobe, BPF};

use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::sync::Arc;
use crate::agent_config_helper::toml_config::{Signature_t};

#[repr(C)]
struct data_t {
    id: u64,
    ret: libc::c_int,
    comm: [u8; 16],   // TASK_COMM_LEN
}

fn do_main(runnable: Arc<AtomicBool>, data: Signature_t) -> Result<(), BccError>{
    let code = include_str!("bpfCode.c");
    // compile the above BPF code!
    let mut module = BPF::new(code)?;

    // load + attach kprobes!
    Kprobe::new()
        .handler("trace_entry")
        .function(&data.pattern_data)
        .attach(&mut module)?;
    Kretprobe::new()
        .handler("trace_return")
        .function(&data.pattern_data)
        .attach(&mut module)?;

        // the "events" table is where the "open file" events get sent
        let table = module.table("events")?;
        // install a callback to print out file open events when they happen
        let mut perf_map = PerfMapBuilder::new(table, perf_data_callback).build()?;
        // print a header
        println!("{:-7} {:-16}", "PID", "COMM");
        // this `.poll()` loop is what makes our callback get called
        while runnable.load(Ordering::SeqCst) {
            perf_map.poll(200);
        }

        Ok(())
}

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data = bytes_to_data_t(x);
        println!(
            "{:-7} {:-16}",
            data.id >> 32,
            bytes_to_string(&data.comm)
        );
    })
}

fn bytes_to_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn bytes_to_data_t(x: &[u8]) -> data_t {
    unsafe { ptr::read_unaligned(x.as_ptr() as *const data_t) }
}

pub fn run(data: Signature_t){
    let runnable = Arc::new(AtomicBool::new(true));
    match do_main(runnable, data) {
        Err(x) => {
            eprintln!("Error: {}", x);
            std::process::exit(1);
        }
        _ => {}
    }
}

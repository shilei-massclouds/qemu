use std::fs::File;
use std::io::{Result, BufReader};
use crate::event::{TE_SIZE, parse_event};
use crate::sysno::MAX_SYSCALL_NBR;

pub(crate) fn analyse(path: &str) -> Result<()> {
    let f = File::open(path)?;
    let mut filesize = f.metadata()?.len() as usize;
    let mut reader = BufReader::new(f);

    while filesize >= TE_SIZE {
        let evt = parse_event(&mut reader, 0)?;
        let advance = evt.head.totalsize as usize;
        println!("tid: {:#x} -> ({})[{:#x}, {:#x}, {}]; pid: {:#x}",
            evt.head.sscratch, evt.head.inout, evt.head.cause,
            evt.head.epc, evt.head.ax[7], evt.head.satp);
        assert!(evt.head.ax[7] < MAX_SYSCALL_NBR);

        filesize -= advance;
    }
    Ok(())
}

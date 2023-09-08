#![allow(dead_code)]
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::process::{Command, Stdio};

static XZ_PATH: &str = "xz";
static GZIP_PATH: &str = "gzip";
static CAT_PATH: &str = "cat";

#[derive(PartialEq, Debug, Default)]
enum InstClass {
    Alu,
    Load,
    Store,
    CondBranch,
    UncondDirectBranch,
    UncondIndirectBranch,
    Fp,
    SlowAlu,
    #[default]
    Undef,
}

impl InstClass {
    fn from_u8(n: u8) -> InstClass {
        match n {
            0 => InstClass::Alu,
            1 => InstClass::Load,
            2 => InstClass::Store,
            3 => InstClass::CondBranch,
            4 => InstClass::UncondDirectBranch,
            5 => InstClass::UncondIndirectBranch,
            6 => InstClass::Fp,
            7 => InstClass::SlowAlu,
            _ => InstClass::Undef,
        }
    }

    fn to_u8(&self) -> u8 {
        match self {
            InstClass::Alu => 0,
            InstClass::Load => 1,
            InstClass::Store => 2,
            InstClass::CondBranch => 3,
            InstClass::UncondDirectBranch => 4,
            InstClass::UncondIndirectBranch => 5,
            InstClass::Fp => 6,
            InstClass::SlowAlu => 7,
            InstClass::Undef => 8,
        }
    }
}

enum OpType {
    Op,
    RetUncond,
    JmpDirectUncond,
    JmpIndirectUncond,
    CallDirectUncond,
    CallIndirectUncond,
    RetCond,
    JmpDirectCond,
    JmpIndirectCond,
    CallDirectCond,
    CallIndirectCond,
    Error,
    Max,
}

impl OpType {
    fn from_u8(n: u8) -> OpType {
        match n {
            2 => OpType::Op,
            3 => OpType::RetUncond,
            4 => OpType::JmpDirectUncond,
            5 => OpType::JmpIndirectUncond,
            6 => OpType::CallDirectUncond,
            7 => OpType::CallIndirectUncond,
            8 => OpType::RetCond,
            9 => OpType::JmpDirectCond,
            10 => OpType::JmpIndirectCond,
            11 => OpType::CallDirectCond,
            12 => OpType::CallIndirectCond,
            13 => OpType::Error,
            14 => OpType::Max,
            _ => OpType::Error,
        }
    }

    fn to_u8(&self) -> u8 {
        match self {
            OpType::Op => 2,
            OpType::RetUncond => 3,
            OpType::JmpDirectUncond => 4,
            OpType::JmpIndirectUncond => 5,
            OpType::CallDirectUncond => 6,
            OpType::CallIndirectUncond => 7,
            OpType::RetCond => 8,
            OpType::JmpDirectCond => 9,
            OpType::JmpIndirectCond => 10,
            OpType::CallDirectCond => 11,
            OpType::CallIndirectCond => 12,
            OpType::Error => 13,
            OpType::Max => 14,
        }
    }
}

#[derive(Debug)]
struct Trace {
    pc: u64,     // program counter
    ea: u64,     // effective address
    target: u64, // branch target

    access_size: u8,
    taken: u8,
    num_input_regs: u8,
    num_output_regs: u8,
    input_reg_names: [u8; 256],
    output_reg_names: [u8; 256],
    output_reg_values: [[u64; 2]; 256],

    inst_type: InstClass,
}

impl Default for Trace {
    fn default() -> Self {
        Trace {
            pc: 0,
            ea: 0,
            target: 0,
            access_size: 0,
            taken: 0,
            num_input_regs: 0,
            num_output_regs: 0,
            input_reg_names: [0; 256],
            output_reg_names: [0; 256],
            output_reg_values: [[0; 2]; 256],
            inst_type: InstClass::Undef,
        }
    }
}

impl Trace {
    fn read(reader: &mut BufReader<Box<dyn Read>>) -> std::io::Result<Self> {
        let mut trace = Trace::default();

        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;

        trace.pc = u64::from_le_bytes(buf);
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        trace.inst_type = InstClass::from_u8(buf[0]);

        match trace.inst_type {
            InstClass::Load | InstClass::Store => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                trace.ea = u64::from_le_bytes(buf);
                let mut buf = [0u8; 1];
                reader.read_exact(&mut buf)?;
                trace.access_size = u8::from_le_bytes(buf);
            }
            InstClass::CondBranch
            | InstClass::UncondDirectBranch
            | InstClass::UncondIndirectBranch => {
                let mut buf = [0u8; 1];
                reader.read_exact(&mut buf)?;
                trace.taken = buf[0];
                if trace.taken != 0 {
                    let mut buf = [0u8; 8];
                    reader.read_exact(&mut buf)?;
                    trace.target = u64::from_le_bytes(buf);
                } else {
                    trace.target = trace.pc + 4;
                    assert_ne!(trace.inst_type, InstClass::UncondDirectBranch);
                    assert_ne!(trace.inst_type, InstClass::UncondIndirectBranch);
                }
            }
            _ => (),
        }

        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        trace.num_input_regs = buf[0];
        for i in 0..trace.num_input_regs {
            reader.read_exact(&mut buf)?;
            trace.input_reg_names[i as usize] = buf[0];
        }

        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        trace.num_output_regs = buf[0];

        for i in 0..trace.num_output_regs {
            reader.read_exact(&mut buf)?;
            trace.output_reg_names[i as usize] = buf[0];
        }

        for i in 0..trace.num_output_regs as usize {
            let mut buf = [0u8; 8];

            if trace.output_reg_names[i] <= 31 || trace.output_reg_names[i] == 64 {
                reader.read_exact(&mut buf)?;
                trace.output_reg_values[i][0] = u64::from_le_bytes(buf);
            } else if trace.output_reg_names[i] >= 32 && trace.output_reg_names[i] < 64 {
                reader.read_exact(&mut buf)?;
                trace.output_reg_values[i][0] = u64::from_le_bytes(buf);
                reader.read_exact(&mut buf)?;
                trace.output_reg_values[i][1] = u64::from_le_bytes(buf);
            } else {
                panic!("Should not reach here, error trace format");
            }
        }

        Ok(trace)
    }
}

fn open_trace_file(file_path: &str, is_stdin: bool) -> std::io::Result<BufReader<Box<dyn Read>>> {
    if is_stdin {
        return Ok(BufReader::new(Box::new(io::stdin())));
    }

    let mut buf = [0u8; 6];

    {
        let mut magic_tester = File::open(file_path)?;
        magic_tester.read_exact(&mut buf)?;
    }

    let cmd;
    let args: Vec<&str>;

    if buf[0] == 0xfd
        && buf[1] == b'7'
        && buf[2] == b'z'
        && buf[3] == b'X'
        && buf[4] == b'Z'
        && buf[5] == 0
    {
        eprintln!("Opening xz file {}", file_path);
        cmd = XZ_PATH;
        args = vec!["-dc", file_path];
    } else if buf[0] == 0x1f && buf[1] == 0x8b {
        eprintln!("Opening gz file {}", file_path);
        cmd = GZIP_PATH;
        args = vec!["-dc", file_path];
    } else {
        eprintln!("Opening file {}", file_path);
        cmd = CAT_PATH;
        args = vec![file_path];
    }

    let output = Command::new(cmd)
        .args(args.clone())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("Command {} {:?} executed failed: {}", cmd, args, e))
        .stdout
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to capture stdout"))?;

    Ok(BufReader::new(Box::new(output)))
}

// Constants
const NUM_INSTR_DESTINATIONS_SPARC: usize = 4;
const NUM_INSTR_DESTINATIONS: usize = 2;
const NUM_INSTR_SOURCES: usize = 4;

#[repr(packed)]
#[derive(Debug)]
struct InputInstr {
    ip: u64,
    is_branch: u8,
    branch_taken: u8,
    destination_registers: [u8; NUM_INSTR_DESTINATIONS],
    source_registers: [u8; NUM_INSTR_SOURCES],
    destination_memory: [u64; NUM_INSTR_DESTINATIONS],
    source_memory: [u64; NUM_INSTR_SOURCES],
}

#[derive(Debug)]
pub struct TraceInfo {
    ip: u64,
    is_branch: u8,
    branch_taken: u8,
    destination_registers: [u8; NUM_INSTR_DESTINATIONS],
    source_registers: [u8; NUM_INSTR_SOURCES],
    destination_memory: [u64; NUM_INSTR_DESTINATIONS],
    source_memory: [u64; NUM_INSTR_SOURCES],
}

pub struct TraceReader {
    handle: BufReader<Box<dyn Read>>,
}

impl TraceReader {
    pub fn new(file_path: &str) -> std::io::Result<Self> {
        let file = open_trace_file(file_path, false)?;
        Ok(TraceReader { handle: file })
    }

    pub fn read(&mut self) -> TraceInfo {
        let mut buf = [0u8; std::mem::size_of::<InputInstr>()];
        self.handle.read_exact(&mut buf).unwrap();
        let trace: InputInstr = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
        TraceInfo {
            ip: trace.ip,
            is_branch: trace.is_branch,
            branch_taken: trace.branch_taken,
            destination_registers: trace.destination_registers,
            source_registers: trace.source_registers,
            destination_memory: trace.destination_memory,
            source_memory: trace.source_memory,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let reader = TraceReader::new("/home/blame/workspace/CRC2_trace/astar_23B.trace.xz");
        if let Ok(mut reader) = reader {
            let trace = reader.read();
            println!("{:?}", trace);
            assert_ne!(trace.ip, 0);
            let trace = reader.read();
            println!("{:?}", trace);
            assert_ne!(trace.ip, 0);
        }
    }
}

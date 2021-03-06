#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "elf")]
use checksec::elf;
#[cfg(feature = "macho")]
use checksec::macho;
#[cfg(feature = "pe")]
use checksec::pe;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum BinType {
    #[cfg(feature = "elf")]
    Elf32,
    #[cfg(feature = "elf")]
    Elf64,
    #[cfg(feature = "pe")]
    PE32,
    #[cfg(feature = "pe")]
    PE64,
    #[cfg(feature = "macho")]
    MachO32,
    #[cfg(feature = "macho")]
    MachO64,
}
#[cfg(not(feature = "color"))]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf32 => write!(f, "ELF32"),
            #[cfg(feature = "elf")]
            Self::Elf64 => write!(f, "ELF64"),
            #[cfg(feature = "pe")]
            Self::PE32 => write!(f, "PE32"),
            #[cfg(feature = "pe")]
            Self::PE64 => write!(f, "PE64"),
            #[cfg(feature = "macho")]
            Self::MachO32 => write!(f, "MachO32"),
            #[cfg(feature = "macho")]
            Self::MachO64 => write!(f, "MachO64"),
        }
    }
}
#[cfg(feature = "color")]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf32 => write!(f, "{}", "ELF32".bold().underline()),
            #[cfg(feature = "elf")]
            Self::Elf64 => write!(f, "{}", "ELF64".bold().underline()),
            #[cfg(feature = "pe")]
            Self::PE32 => write!(f, "{}", "PE32".bold().underline()),
            #[cfg(feature = "pe")]
            Self::PE64 => write!(f, "{}", "PE64".bold().underline()),
            #[cfg(feature = "macho")]
            Self::MachO32 => write!(f, "{}", "MachO32".bold().underline()),
            #[cfg(feature = "macho")]
            Self::MachO64 => write!(f, "{}", "MachO64".bold().underline()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum BinSpecificProperties {
    #[cfg(feature = "elf")]
    Elf(elf::CheckSecResults),
    #[cfg(feature = "pe")]
    PE(pe::CheckSecResults),
    #[cfg(feature = "macho")]
    MachO(macho::CheckSecResults),
}
impl fmt::Display for BinSpecificProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            #[cfg(feature = "elf")]
            Self::Elf(b) => write!(f, "{}", b),
            #[cfg(feature = "pe")]
            Self::PE(b) => write!(f, "{}", b),
            #[cfg(feature = "macho")]
            Self::MachO(b) => write!(f, "{}", b),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Binary {
    pub binarytype: BinType,
    pub file: String,
    pub properties: BinSpecificProperties,
}
#[cfg(not(feature = "color"))]
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: | {} | File: {}",
            self.binarytype, self.properties, self.file
        )
    }
}
#[cfg(feature = "color")]
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: | {} | {} {}",
            self.binarytype,
            self.properties,
            "File:".bold().underline(),
            self.file.bright_blue()
        )
    }
}
impl Binary {
    pub const fn new(
        binarytype: BinType,
        file: String,
        properties: BinSpecificProperties,
    ) -> Self {
        Self { binarytype, file, properties }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Binaries {
    pub binaries: Vec<Binary>,
}
impl Binaries {
    pub fn new(binaries: Vec<Binary>) -> Self {
        Self { binaries }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Process {
    pub pid: usize,
    pub binary: Vec<Binary>,
}
impl Process {
    pub fn new(pid: usize, binary: Vec<Binary>) -> Self {
        Self { pid, binary }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Processes {
    pub processes: Vec<Process>,
}
impl Processes {
    pub fn new(processes: Vec<Process>) -> Self {
        Self { processes }
    }
}

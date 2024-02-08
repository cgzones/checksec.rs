#![warn(clippy::pedantic)]
// Do not require 1.65.0
#![allow(clippy::manual_let_else)]
extern crate clap;
extern crate core;
extern crate goblin;
extern crate ignore;
extern crate serde_json;
extern crate sysinfo;

use clap::CommandFactory;
use clap::Parser;
use clap::Subcommand;
use clap::{arg, command};
use either::Either;
use goblin::error::Error;
#[cfg(feature = "macho")]
use goblin::mach::{Mach, SingleArch::Archive, SingleArch::MachO};
use goblin::Object;
use ignore::WalkBuilder;
#[cfg(all(feature = "maps", target_os = "linux"))]
use itertools::Itertools;
use memmap2::Mmap;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use serde_json::{json, to_string_pretty};
use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

use std::any::type_name_of_val;
use std::collections::HashMap;
#[cfg(all(target_os = "linux", feature = "elf"))]
use std::collections::HashSet;
use std::ffi::OsStr;
#[cfg(feature = "archives")]
use std::io::Cursor;
use std::io::IsTerminal;
use std::io::{BufRead, ErrorKind, Read};
#[cfg(all(feature = "color", not(target_os = "windows")))]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{fmt, fs, process};

#[cfg(feature = "color")]
use colored::{ColoredString, Colorize};

#[cfg(feature = "color")]
use colored_json::to_colored_json_auto;
#[cfg(feature = "archives")]
use compress_tools::{ArchiveContents, ArchiveIterator};

mod binary;
mod proc;

use binary::{BinSpecificProperties, BinType, Binary, Blob};
use proc::{Process, Processes};

#[cfg(feature = "elf")]
use checksec::elf;
#[cfg(all(target_os = "linux", feature = "elf"))]
use checksec::elf::LibraryLookup;
#[cfg(all(target_os = "linux", feature = "elf"))]
use checksec::ldso::LdSoError;
#[cfg(feature = "macho")]
use checksec::macho;
use checksec::output;
#[cfg(feature = "pe")]
use checksec::pe;
#[cfg(all(target_os = "linux", feature = "elf"))]
use checksec::shared::VecRpath;
use checksec::{bold, underline};

#[cfg(all(feature = "color", target_os = "windows"))]
fn print_filename(file: &Path) -> ColoredString {
    file.display().to_string().bright_blue()
}

#[cfg(all(feature = "color", not(target_os = "windows")))]
fn print_filename(file: &Path) -> ColoredString {
    match std::fs::metadata(file) {
        Ok(md) => {
            #[cfg(target_os = "linux")]
            fn has_filecaps(file: &Path) -> bool {
                xattr::get(file, "security.capability")
                    .unwrap_or(None)
                    .is_some()
            }
            #[cfg(not(target_os = "linux"))]
            fn has_filecaps(_file: &Path) -> bool {
                false
            }

            let mode = md.permissions().mode();
            if mode & 0o4000 == 0o4000 {
                file.display().to_string().white().on_red()
            } else if mode & 0o2000 == 0o2000 {
                file.display().to_string().black().on_yellow()
            } else if has_filecaps(file) {
                file.display().to_string().black().on_blue()
            } else {
                file.display().to_string().bright_blue()
            }
        }
        Err(_) => file.display().to_string().bright_blue(),
    }
}

#[cfg(not(feature = "color"))]
fn print_filename(file: &Path) -> impl std::fmt::Display + '_ {
    file.display()
}

fn print_binary_results(binaries: &[Binary], settings: &output::Settings) {
    match settings.format {
        output::Format::Json => {
            println!("{}", &json!(binaries));
        }
        output::Format::JsonPretty => {
            #[cfg(feature = "color")]
            if settings.color {
                if let Ok(colored_json) =
                    to_colored_json_auto(&json!(binaries))
                {
                    println!("{colored_json}");
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{json_str}");
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{json_str}");
            }
        }
        output::Format::Text => {
            let mut first = true;

            for binary in binaries {
                if !first && settings.libraries {
                    println!();
                }
                first = false;

                for blob in &binary.blobs {
                    println!(
                        "{}: | {} | {} {}",
                        blob.binarytype,
                        blob.properties,
                        underline!(bold!("File:")),
                        print_filename(&binary.file)
                    );
                }
                if settings.libraries {
                    for library in &binary.libraries {
                        for blob in &library.blobs {
                            println!(
                                "{}: | {} | {} {}",
                                blob.binarytype,
                                blob.properties,
                                underline!(bold!("File:")),
                                print_filename(&library.file)
                            );
                        }
                    }
                }
            }
        }
    }
}

fn print_process_results(
    processes: &Processes,
    settings: &output::Settings,
    maps: bool,
) {
    match settings.format {
        output::Format::Json => {
            println!("{}", &json!(processes));
        }
        output::Format::JsonPretty => {
            #[cfg(feature = "color")]
            if settings.color {
                if let Ok(colored_json) =
                    to_colored_json_auto(&json!(processes))
                {
                    println!("{colored_json}");
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{json_str}");
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{json_str}");
            }
        }
        output::Format::Text => {
            let mut first = true;

            for process in &processes.processes {
                if !first && settings.libraries {
                    println!();
                }
                first = false;

                for blob in &process.binary.blobs {
                    println!(
                        "{}({})\n \u{21aa} {}: | {} | {} {}",
                        bold!(process
                            .binary
                            .file
                            .file_name()
                            .unwrap_or_else(|| OsStr::new("n/a"))
                            .to_string_lossy()),
                        process.pid,
                        blob.binarytype,
                        blob.properties,
                        underline!(bold!("File:")),
                        print_filename(&process.binary.file)
                    );
                }

                #[cfg(all(
                    feature = "maps",
                    any(target_os = "linux", target_os = "windows")
                ))]
                if let Some(libraries) = &process.libraries {
                    for library in libraries {
                        for blob in &library.blobs {
                            println!(
                                " \u{21aa} {}: | {} | {} {}",
                                blob.binarytype,
                                blob.properties,
                                underline!(bold!("File:")),
                                print_filename(&library.file)
                            );
                        }
                    }
                }
                #[cfg(all(
                    feature = "maps",
                    any(target_os = "linux", target_os = "windows")
                ))]
                if maps {
                    if let Some(maps) = &process.maps {
                        println!("{:>12}", "\u{21aa} Maps:");
                        for map in maps {
                            println!("\t{map}");
                        }
                    }
                }
            }
        }
    }
}

struct Lookup {
    #[cfg(all(target_os = "linux", feature = "elf"))]
    elf: LibraryLookup,
}

impl Lookup {
    #[cfg(all(target_os = "linux", feature = "elf"))]
    fn elf_lookup(
        &self,
        binarypath: &Path,
        rpath: &VecRpath,
        runpath: &VecRpath,
        libfilename: &str,
    ) -> Option<PathBuf> {
        self.elf.lookup(binarypath, rpath, runpath, libfilename)
    }
}

enum ParseError {
    Goblin(goblin::error::Error),
    IO(std::io::Error),
    #[cfg(all(target_os = "linux", feature = "elf"))]
    LdSo(LdSoError),
    #[cfg(feature = "archives")]
    Decompress(compress_tools::Error),
    #[allow(dead_code)]
    Unimplemented(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Goblin(e) => e.fmt(f),
            Self::IO(e) => e.fmt(f),
            #[cfg(all(target_os = "linux", feature = "elf"))]
            Self::LdSo(e) => {
                write!(f, "Failed to initialize library lookup: {e}")
            }
            #[cfg(feature = "archives")]
            Self::Decompress(e) => e.fmt(f),
            Self::Unimplemented(str) => {
                write!(f, "Support for files of type {str} not implemented")
            }
        }
    }
}

impl From<goblin::error::Error> for ParseError {
    fn from(err: goblin::error::Error) -> ParseError {
        ParseError::Goblin(err)
    }
}

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> ParseError {
        ParseError::IO(err)
    }
}

#[cfg(all(target_os = "linux", feature = "elf"))]
impl From<LdSoError> for ParseError {
    fn from(err: LdSoError) -> ParseError {
        ParseError::LdSo(err)
    }
}

#[cfg(feature = "archives")]
impl From<compress_tools::Error> for ParseError {
    fn from(err: compress_tools::Error) -> ParseError {
        ParseError::Decompress(err)
    }
}

type Cache = Arc<Mutex<HashMap<PathBuf, Vec<Binary>>>>;

#[allow(clippy::needless_pass_by_value)]
fn parse(
    file: &Path,
    scan_archives: bool,
    cache: Option<Cache>,
) -> Result<Vec<Binary>, ParseError> {
    if let Some(ref cache) = cache {
        let cache = cache.lock().unwrap();
        if let Some(entry) = cache.get(file) {
            return Ok(entry.clone());
        }
    }

    let mut fp = fs::File::open(file)?;
    let buffer = if let Ok(buf) = unsafe { Mmap::map(&fp) } {
        Either::Left(buf)
    } else {
        let size = fp.metadata().map(|m| m.len()).unwrap_or(0);
        let mut buf = Vec::with_capacity(usize::try_from(size).unwrap());
        fp.read_to_end(&mut buf)?;
        Either::Right(buf)
    };

    let result = parse_bytes(&buffer, scan_archives, file)?;
    if let Some(ref cache) = cache {
        let mut cache = cache.lock().unwrap();
        cache.insert(file.to_path_buf(), result.clone());
    }

    Ok(result)
}

#[allow(clippy::too_many_lines)]
fn parse_bytes(
    bytes: &[u8],
    scan_archives: bool,
    file: &Path,
) -> Result<Vec<Binary>, ParseError> {
    match Object::parse(bytes)? {
        #[cfg(feature = "elf")]
        Object::Elf(elf) => {
            let results = elf::CheckSecResults::parse(&elf, bytes);
            let bin_type =
                if elf.is_64 { BinType::Elf64 } else { BinType::Elf32 };
            Ok(vec![Binary::new(
                file.to_path_buf(),
                vec![Blob::new(bin_type, BinSpecificProperties::Elf(results))],
            )])
        }
        #[cfg(feature = "pe")]
        Object::PE(pe) => {
            let results = pe::CheckSecResults::parse(&pe, bytes);
            let bin_type =
                if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
            Ok(vec![Binary::new(
                file.to_path_buf(),
                vec![Blob::new(bin_type, BinSpecificProperties::PE(results))],
            )])
        }
        #[cfg(feature = "macho")]
        Object::Mach(mach) => {
            match mach {
                Mach::Binary(macho) => {
                    let results = macho::CheckSecResults::parse(&macho);
                    let bin_type = if macho.is_64 {
                        BinType::MachO64
                    } else {
                        BinType::MachO32
                    };
                    Ok(vec![Binary::new(
                        file.to_path_buf(),
                        vec![Blob::new(
                            bin_type,
                            BinSpecificProperties::MachO(results),
                        )],
                    )])
                }
                Mach::Fat(fatmach) => {
                    let mut fat_bins: Vec<Binary> = Vec::new();
                    let mut fat_blobs: Vec<Blob> = Vec::new();
                    for (idx, fatarch) in fatmach.iter_arches().enumerate() {
                        if let Ok(container) = fatmach.get(idx) {
                            match container {
                                MachO(mach) => {
                                    let results =
                                        macho::CheckSecResults::parse(&mach);
                                    let bin_type = if mach.is_64 {
                                        BinType::MachO64
                                    } else {
                                        BinType::MachO32
                                    };
                                    fat_blobs.push(Blob::new(
                                        bin_type,
                                        BinSpecificProperties::MachO(results),
                                    ));
                                }
                                Archive(archive) => {
                                    let fatarch = fatarch?;
                                    if let Some(archive_bytes) = bytes.get(
                                        fatarch.offset as usize
                                            ..(fatarch.offset + fatarch.size)
                                                as usize,
                                    ) {
                                        fat_bins.append(&mut parse_archive(
                                            &archive,
                                            file,
                                            archive_bytes,
                                        ));
                                    } else {
                                        Err(goblin::error::Error::Malformed("Archive refers to invalid position".to_string()))?;
                                    }
                                }
                            }
                        }
                    }
                    fat_bins.push(Binary::new(file.to_path_buf(), fat_blobs));
                    Ok(fat_bins)
                }
            }
        }
        #[cfg(not(feature = "elf"))]
        Object::Elf(_) => Err(ParseError::Unimplemented("ELF")),
        #[cfg(not(feature = "pe"))]
        Object::PE(_) => Err(ParseError::Unimplemented("PE")),
        #[cfg(not(feature = "macho"))]
        Object::Mach(_) => Err(ParseError::Unimplemented("MachO")),
        Object::Archive(archive) => {
            if scan_archives {
                Ok(parse_archive(&archive, file, bytes))
            } else {
                Ok(vec![])
            }
        }
        #[cfg(feature = "archives")]
        Object::Unknown(magic) => {
            if !scan_archives {
                return Ok(vec![]);
            }

            let mut results = Vec::new();
            let mut handled = false;

            let mut name = String::default();
            let mut buffer = Vec::new();

            for content in ArchiveIterator::from_read(Cursor::new(bytes))? {
                match content {
                    ArchiveContents::StartOfEntry(s, _) => {
                        name = s;
                        buffer.clear();
                    }
                    ArchiveContents::DataChunk(v) => buffer.extend(v),
                    ArchiveContents::EndOfEntry => {
                        if buffer != bytes {
                            handled = true;

                            if let Ok(mut res) = parse_bytes(
                                &buffer,
                                true,
                                Path::new(&format!(
                                    "{}\u{2794}{}",
                                    file.display(),
                                    name
                                )),
                            ) {
                                results.append(&mut res);
                            }
                        }
                    }
                    ArchiveContents::Err(e) => Err(e)?,
                }
            }

            if handled {
                Ok(results)
            } else {
                Err(ParseError::Goblin(Error::BadMagic(magic)))
            }
        }
        #[cfg(not(feature = "archives"))]
        Object::Unknown(magic) => {
            Err(ParseError::Goblin(Error::BadMagic(magic)))
        }
        obj => Err(ParseError::Unimplemented(type_name_of_val(&obj))),
    }
}

fn parse_archive(
    archive: &goblin::archive::Archive,
    file: &Path,
    bytes: &[u8],
) -> Vec<Binary> {
    archive
        .members()
        .iter()
        .filter_map(|member_name| match archive.extract(member_name, bytes) {
            Ok(ext_bytes) => parse_bytes(
                ext_bytes,
                true,
                Path::new(&format!(
                    "{}\u{2794}{}",
                    file.display(),
                    member_name
                )),
            )
            .ok(),
            Err(err) => {
                eprintln!(
                    "Failed to extract member {} of {}: {}",
                    member_name,
                    file.display(),
                    err
                );
                None
            }
        })
        .flatten()
        .collect()
}

#[cfg(not(all(target_os = "linux", feature = "elf")))]
fn parse_single_file(
    file: &Path,
    _scan_dynlibs: bool,
) -> Result<Vec<Binary>, ParseError> {
    parse(file, true, None)
}

#[cfg(not(all(target_os = "linux", feature = "elf")))]
fn parse_file_impl(
    file: &Path,
    _scan_dynlibs: bool,
    scan_archives: bool,
    _lookup: Option<&Lookup>,
    cache: Option<Cache>,
) -> Result<Vec<Binary>, ParseError> {
    parse(file, scan_archives, cache)
}

#[cfg(all(target_os = "linux", feature = "elf"))]
fn scan_dependencies(
    binary: &Binary,
    lookup: &Lookup,
    scanned: &HashSet<PathBuf>,
) -> HashSet<PathBuf> {
    let mut to_scan = HashSet::new();

    for blob in &binary.blobs {
        #[allow(irrefutable_let_patterns)]
        if let BinSpecificProperties::Elf(elf_properties) = &blob.properties {
            for dynlib in &elf_properties.dynlibs {
                match lookup.elf_lookup(
                    &binary.file,
                    &elf_properties.rpath,
                    &elf_properties.runpath,
                    dynlib,
                ) {
                    Some(path) => {
                        if scanned.contains(&path) {
                            continue;
                        }
                        to_scan.insert(path);
                    }
                    None => {
                        eprintln!(
                            "Library {} for {} not found",
                            underline!(dynlib),
                            binary.file.display()
                        );
                    }
                }
            }
        }
    }

    to_scan
}

#[cfg(all(target_os = "linux", feature = "elf"))]
#[allow(clippy::needless_pass_by_value)]
fn parse_dependencies(
    binary: &mut Binary,
    lookup: &Lookup,
    cache: Option<Cache>,
) {
    let mut scanned = HashSet::new();
    let mut to_scan = scan_dependencies(binary, lookup, &scanned);

    while !to_scan.is_empty() {
        let mut results: Vec<Binary> = to_scan
            .par_iter()
            .filter_map(|lib| match parse(lib, true, cache.clone()) {
                Ok(bins) => Some(bins),
                Err(err) => {
                    eprintln!(
                        "Failed to parse {} for {}: {}",
                        lib.display(),
                        binary.file.display(),
                        err
                    );
                    None
                }
            })
            .flatten()
            .collect();

        scanned.extend(to_scan);

        to_scan = results
            .par_iter()
            .flat_map(|bin| scan_dependencies(bin, lookup, &scanned))
            .collect();

        binary.libraries.append(&mut results);
    }
}

#[cfg(all(target_os = "linux", feature = "elf"))]
#[allow(clippy::needless_pass_by_value)]
fn parse_file_impl(
    file: &Path,
    scan_dynlibs: bool,
    scan_archives: bool,
    lookup: Option<&Lookup>,
    cache: Option<Cache>,
) -> Result<Vec<Binary>, ParseError> {
    let mut results = parse(file, scan_archives, cache.clone())?;

    if !scan_dynlibs || lookup.is_none() {
        return Ok(results);
    }

    let lookup = lookup.as_ref().unwrap();

    for result in &mut results {
        parse_dependencies(result, lookup, cache.clone());
    }

    Ok(results)
}

#[cfg(all(target_os = "linux", feature = "elf"))]
fn parse_single_file(
    file: &Path,
    scan_dynlibs: bool,
) -> Result<Vec<Binary>, ParseError> {
    if !scan_dynlibs {
        return parse(file, true, None);
    }

    let lookup = Lookup { elf: LibraryLookup::new()? };

    parse_file_impl(file, true, true, Some(&lookup), None)
}

fn walk(
    basepath: &Path,
    scan_dynlibs: bool,
    scan_same_filesystem: bool,
    scan_archives: bool,
) -> Vec<Binary> {
    let lookup = if scan_dynlibs {
        Some(Lookup {
            #[cfg(all(target_os = "linux", feature = "elf"))]
            elf: LibraryLookup::new().unwrap_or_else(|err| {
                eprintln!("Failed to initialize library lookup: {err}");
                process::exit(1)
            }),
        })
    } else {
        None
    };

    let cache = Arc::new(Mutex::new(HashMap::new()));

    WalkBuilder::new(basepath)
        .same_file_system(scan_same_filesystem)
        .build()
        .flatten()
        .filter(|entry| {
            entry.file_type().filter(std::fs::FileType::is_file).is_some()
        })
        .par_bridge()
        .filter_map(|entry| {
            parse_file_impl(
                entry.path(),
                scan_dynlibs,
                scan_archives,
                lookup.as_ref(),
                Some(Arc::clone(&cache)),
            )
            .ok()
        })
        .flatten()
        .collect()
}

#[cfg(all(feature = "maps", target_os = "linux"))]
#[allow(clippy::needless_pass_by_value)]
fn parse_process_libraries(
    process: &sysinfo::Process,
    cache: Option<Cache>,
) -> Result<Vec<Binary>, std::io::Error> {
    Ok(Process::parse_maps(process.pid().as_u32() as usize)?
        .into_iter()
        .filter(|m| m.flags.x)
        .filter_map(|m| m.pathname)
        .filter(|p| p.is_absolute() && process.exe().is_some_and(|e| e != p))
        .map(|p| match p.file_name() {
            Some(file_name) => match file_name.to_str() {
                Some(file_name) => {
                    match file_name.strip_suffix(" (deleted)") {
                        Some(s) => {
                            let mut pb = PathBuf::from(
                                p.parent().unwrap_or(Path::new("/")),
                            );
                            pb.push(s);
                            Either::Left(pb)
                        }
                        None => Either::Right(p),
                    }
                }
                None => Either::Right(p),
            },
            None => Either::Right(p),
        })
        .unique()
        .par_bridge()
        .filter_map(|p| {
            parse(&p, true, cache.clone())
                .map_err(|err| {
                    if let ParseError::IO(ref e) = err {
                        if e.kind() == ErrorKind::NotFound
                            || e.kind() == ErrorKind::PermissionDenied
                        {
                            return;
                        }
                    }

                    eprintln!(
                        "Failed to parse '{}' for process ID {}: {}",
                        p.display(),
                        process.pid(),
                        err
                    );
                })
                .ok()
        })
        .flatten()
        .collect::<Vec<Binary>>())
}

#[cfg(not(all(feature = "maps", target_os = "linux")))]
#[allow(clippy::needless_pass_by_value)]
fn parse_process_libraries(
    _process: &sysinfo::Process,
    _cache: Option<Cache>,
) -> Result<Vec<Binary>, std::io::Error> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "parse_process_libraries()",
    ))
}

fn parse_processes<'a, I>(
    processes: I,
    quiet: bool,
    scan_dynlibs: bool,
) -> Vec<Process>
where
    I: Iterator<Item = &'a sysinfo::Process> + Send,
{
    let cache = Arc::new(Mutex::new(HashMap::new()));

    processes
        .par_bridge()
        .filter_map(|process| {
            let exe = process.exe()?;
            match parse(exe, true, Some(Arc::clone(&cache))) {
                Err(err) => {
                    if quiet {
                        if let ParseError::IO(ref e) = err {
                            if e.kind() == ErrorKind::NotFound
                                || e.kind() == ErrorKind::PermissionDenied
                            {
                                return None;
                            }
                        }
                    }

                    eprintln!(
                        "Can not parse process {:?} with ID {}: {}",
                        process.name(),
                        process.pid(),
                        err
                    );

                    None
                }
                Ok(bins) => Some(
                    bins.into_iter()
                        .map(|bin| {
                            Process::new(
                                process.pid().as_u32() as usize,
                                bin,
                                if scan_dynlibs {
                                    parse_process_libraries(
                                        process,
                                        Some(Arc::clone(&cache)),
                                    )
                                    .ok()
                                } else {
                                    None
                                },
                            )
                        })
                        .collect::<Vec<proc::Process>>(),
                ),
            }
        })
        .flatten()
        .collect()
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about,
    override_usage = "checksec [OPTIONS] [COMMAND]\n       command | checksec [OPTIONS]"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Disables color output
    #[arg(long)]
    no_color: bool,
    /// Output format
    #[arg(long, default_value_t = output::Format::Text)]
    format: output::Format,
    /// Scan shared libraries
    #[arg(short, long)]
    libraries: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan executables by path
    #[command(arg_required_else_help = true)]
    File {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Scan only files on the same filesystem
        #[arg(short = 'S', long)]
        same_filesystem: bool,
        /// Scan archives, e.g. distribution packages (.deb) or static libraries (.a)
        #[arg(short = 'A', long)]
        archives: bool,
    },
    /// Scan processes by PID
    #[command(arg_required_else_help = true)]
    ProcID {
        #[arg(required = true)]
        pids: Vec<sysinfo::Pid>,
        /// Include process memory maps (linux only)
        #[arg(short, long)]
        maps: bool,
    },
    /// Scan processes by name
    #[command(arg_required_else_help = true)]
    ProcName {
        #[arg(required = true)]
        procnames: Vec<String>,
        /// Include process memory maps (linux only)
        #[arg(short, long)]
        maps: bool,
    },
    /// Scan all running processes
    ProcAll {
        /// Include process memory maps (linux only)
        #[arg(short, long)]
        maps: bool,
    },
}

fn main() {
    let args = Cli::parse();

    let format = args.format;

    let settings = output::Settings::set(
        #[cfg(feature = "color")]
        !args.no_color,
        format,
        args.libraries,
    );

    match args.command {
        Some(Commands::File { paths, same_filesystem, archives }) => {
            let results =
                scan_paths(&paths, args.libraries, same_filesystem, archives);
            print_binary_results(&results, &settings);
        }
        Some(Commands::ProcID { pids, maps }) => {
            let results = scan_pids(&pids, args.libraries);
            if results.is_empty() {
                process::exit(1);
            }
            print_process_results(&Processes::new(results), &settings, maps);
        }
        Some(Commands::ProcName { procnames, maps }) => {
            let results = scan_procnames(&procnames, args.libraries);
            if results.is_empty() {
                process::exit(1);
            }
            print_process_results(&Processes::new(results), &settings, maps);
        }
        Some(Commands::ProcAll { maps }) => {
            let results = scan_all_processes(args.libraries);
            if results.is_empty() {
                eprintln!("No running process found");
                process::exit(1);
            }
            print_process_results(&Processes::new(results), &settings, maps);
        }
        None => {
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                let mut cmd = Cli::command();
                let _ = cmd.print_help();
                process::exit(1);
            }

            let results: Vec<Binary> = stdin
                .lock()
                .lines()
                .map(|line| {
                    line.expect("Cannot read line from standard input")
                })
                .filter_map(|file| {
                    let path = Path::new(&file);
                    if path.is_file() {
                        parse_single_file(path, args.libraries).ok()
                    } else {
                        None
                    }
                })
                .flatten()
                .collect();
            print_binary_results(&results, &settings);
        }
    };
}

fn scan_paths(
    paths: &[PathBuf],
    libraries: bool,
    scan_same_filesystem: bool,
    scan_archives: bool,
) -> Vec<Binary> {
    let mut results = Vec::new();

    for path in paths {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "Failed to check path {}: {}",
                    underline!(path.display().to_string()),
                    e
                );
                continue;
            }
        };

        if metadata.is_file() {
            // TODO: reuse cache
            match parse_single_file(path, libraries) {
                Ok(mut res) => results.append(&mut res),
                Err(msg) => {
                    eprintln!(
                        "Cannot parse binary file {}: {}",
                        underline!(path.display().to_string()),
                        msg
                    );
                }
            }
            continue;
        }

        if metadata.is_dir() {
            // TODO: reuse cache
            results.append(&mut walk(
                path,
                libraries,
                scan_same_filesystem,
                scan_archives,
            ));
            continue;
        }

        eprintln!(
            "{} is an unsupported type of file",
            underline!(path.display().to_string())
        );
    }

    results
}

fn get_system() -> System {
    System::new_with_specifics(RefreshKind::new().with_processes(
        ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet),
    ))
}

fn scan_pids(pids: &[sysinfo::Pid], libraries: bool) -> Vec<Process> {
    let system = get_system();

    parse_processes(
        pids.iter().filter_map(|pid| {
            if let Some(process) = system.process(*pid) {
                Some(process)
            } else {
                eprintln!("No process found with ID {pid}");
                None
            }
        }),
        false,
        libraries,
    )
}

fn scan_procnames(procnames: &[String], libraries: bool) -> Vec<Process> {
    let system = get_system();

    parse_processes(
        procnames
            .iter()
            .filter_map(|procname| {
                // processes_by_name() returns an Iterator not implementing Send
                let procs: Vec<_> = system
                    .processes_by_name(procname.as_ref())
                    .filter(|process| process.thread_kind().is_none())
                    .collect();
                if procs.is_empty() {
                    eprintln!("No process found with name {procname}");
                    None
                } else {
                    Some(procs)
                }
            })
            .flatten(),
        false,
        libraries,
    )
}

fn scan_all_processes(libraries: bool) -> Vec<Process> {
    let system = get_system();

    parse_processes(
        system
            .processes()
            .iter()
            .filter(|(_pid, process)| process.thread_kind().is_none())
            .map(|(_pid, process)| process),
        true,
        libraries,
    )
}

use object::SectionFlags;

pub fn is_readable(flags: SectionFlags) -> bool {
    match flags {
        SectionFlags::Coff { characteristics } => {
            (characteristics & 0x40000000) != 0
        }
        SectionFlags::Elf { sh_flags } => {
            (sh_flags & 0x2) != 0
        }
        SectionFlags::MachO { flags: _ } => {
            true
        }
        SectionFlags::Xcoff { s_flags: _ } => {
            true
        }
        SectionFlags::None => false,
        _ => false,
    }
}

pub fn is_writable(flags: SectionFlags) -> bool {
    match flags {
        SectionFlags::Coff { characteristics } => {
            (characteristics & 0x80000000) != 0
        }
        SectionFlags::Elf { sh_flags } => {
            (sh_flags & 0x1) != 0
        }
        SectionFlags::MachO { flags: _ } => {
            false
        }
        SectionFlags::Xcoff { s_flags: _ } => false,
        SectionFlags::None => false,
        _ => false,
    }
}

pub fn is_executable(flags: SectionFlags) -> bool {
    match flags {
        SectionFlags::Coff { characteristics } => {
            (characteristics & 0x20000000) != 0
        }
        SectionFlags::Elf { sh_flags } => {
            (sh_flags & 0x4) != 0
        }
        SectionFlags::MachO { flags: _ } => {
            false
        }
        SectionFlags::Xcoff { s_flags: _ } => false,
        SectionFlags::None => false,
        _ => false,
    }
}
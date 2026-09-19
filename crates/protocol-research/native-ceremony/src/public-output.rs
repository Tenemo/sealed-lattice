use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

/// A diagnostic public record is exposed at its final name only after its
/// complete stream has flushed successfully. Failed staging remains diagnostic.
pub struct PublicOutput {
    writer: BufWriter<File>,
    staged: PathBuf,
    destination: PathBuf,
    bytes: u64,
}
impl PublicOutput {
    pub fn create(destination: impl AsRef<Path>) -> io::Result<Self> {
        let destination = destination.as_ref().to_path_buf();
        if destination.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Public output already exists",
            ));
        }
        let name = destination
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing output name"))?;
        let mut staged_name = name.to_os_string();
        staged_name.push(".staged");
        let staged = destination.with_file_name(staged_name);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        Ok(Self {
            writer: BufWriter::new(options.open(&staged)?),
            staged,
            destination,
            bytes: 0,
        })
    }
    pub fn finish(mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        if self.writer.get_ref().metadata()?.len() != self.bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Staged output length differs",
            ));
        }
        let Self {
            writer,
            staged,
            destination,
            bytes,
        } = self;
        drop(writer);
        if destination.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Public output appeared during staging",
            ));
        }
        fs::rename(staged, &destination)?;
        if fs::metadata(destination)?.len() != bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Published output length differs",
            ));
        }
        Ok(())
    }
}
impl Write for PublicOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.writer.write(bytes)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("Output length overflow"))?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

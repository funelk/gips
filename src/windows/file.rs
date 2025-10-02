use std::ops::Deref;

use windows::{core::HSTRING, Win32::Storage::FileSystem};

use super::handle::Handle;

#[derive(Debug, Default)]
pub struct Builder {
    file_name: String,
    desired_access: u32,
    share_mode: FileSystem::FILE_SHARE_MODE,
    creation_disposition: FileSystem::FILE_CREATION_DISPOSITION,
    flags_and_attributes: FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
}

impl Builder {
    pub fn new<S: Into<String>>(file_name: S) -> Builder {
        Builder {
            file_name: file_name.into(),
            ..Default::default()
        }
    }

    /// The name of the file or device to be created or opened. You may use either forward slashes (/) or backslashes (\) in this name.
    ///
    /// For information on special device names, see Defining an MS-DOS Device Name.
    ///  
    /// To create a file stream, specify the name of the file, a colon, and then the name of the stream. For more information, see File Streams.
    ///  
    /// By default, the name is limited to MAX_PATH characters.
    /// To extend this limit to 32,767 wide characters, prepend "\\?\" to the path. For more information,
    /// see Naming Files, Paths, and Namespaces.
    pub fn file_name(mut self, name: &str) -> Self {
        self.file_name = name.into();
        self
    }

    /// The requested access to the file or device, which can be summarized as read, write, both or neither zero).
    ///
    /// The most commonly used values are GENERIC_READ, GENERIC_WRITE, or both (GENERIC_READ | GENERIC_WRITE).
    /// For more information, see Generic Access Rights, File Security and Access Rights, File Access Rights Constants, and ACCESS_MASK.
    pub fn desired_access(mut self, access: u32) -> Self {
        self.desired_access |= access;
        self
    }

    /// The requested sharing mode of the file or device, which can be read, write, both, delete, all of these, or none (refer to the following table).
    ///  Access requests to attributes or extended attributes are not affected by this flag.
    ///
    /// If this parameter is zero and CreateFile succeeds, the file or device cannot be shared and cannot be opened again until the handle to the file or device is closed.
    ///
    /// You cannot request a sharing mode that conflicts with the access mode that is specified in an existing request that has an open handle.
    /// CreateFile would fail and the GetLastError function would return ERROR_SHARING_VIOLATION.
    ///
    /// To enable a process to share a file or device while another process has the file or device open, use a compatible combination of one or more of the following values.
    /// For more information about valid combinations of this parameter with the dwDesiredAccess parameter, see Creating and Opening Files.
    pub fn share_mode(mut self, mode: FileSystem::FILE_SHARE_MODE) -> Self {
        self.share_mode = mode;
        self
    }

    /// An action to take on a file or device that exists or does not exist.
    ///
    /// For devices other than files, this parameter is usually set to OPEN_EXISTING.
    pub fn creation_disposition(
        mut self,
        disposition: FileSystem::FILE_CREATION_DISPOSITION,
    ) -> Self {
        self.creation_disposition = disposition;
        self
    }

    //. The file or device attributes and flags, FILE_ATTRIBUTE_NORMAL being the most common default value for files.
    pub fn flags_and_attributes(
        mut self,
        attributes: FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
    ) -> Self {
        self.flags_and_attributes |= attributes;
        self
    }

    pub fn build(&self) -> Result<File, ::windows::core::Error> {
        let handle = Handle::try_from(unsafe {
            FileSystem::CreateFileW(
                &HSTRING::from(self.file_name.as_str()),
                self.desired_access,
                self.share_mode,
                None,
                self.creation_disposition,
                // We write synchronously, otherwise may incorrectly report that the write operation is complete
                self.flags_and_attributes,
                None,
            )?
        })?;
        Ok(File {
            name: self.file_name.clone(),
            handle,
        })
    }
}

#[derive(Debug)]
pub struct File {
    name: String,
    handle: Handle,
}

impl Deref for File {
    type Target = Handle;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl std::io::Read for File {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.handle.read(buf)?)
    }
}
impl std::io::Write for File {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(self.handle.write(buf)?)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(self.handle.flush()?)
    }
}

impl From<File> for Handle {
    fn from(file: File) -> Self {
        file.handle
    }
}

impl File {
    pub fn builder<S: Into<String>>(file_name: S) -> Builder {
        Builder::new(file_name)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

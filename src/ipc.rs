cfg_if::cfg_if! {
  if #[cfg(target_os = "macos")] {
    mod macos;
    pub use macos::{Listener, Endpoint, Pod, Connection};
  }
  else if #[cfg(target_os = "linux")] {
    mod linux;
  }
  else if #[cfg(target_os = "windows")] {
    mod windows;
    pub use windows::{Listener, Endpoint, Pod, Connection};
  }
  else {
    compile_error!("Unsupported platform for IPC. Only Windows, macOS, and Linux are supported.");
  }
}

#[cfg(target_os = "macos")]
use crate::mach;
#[cfg(windows)]
use crate::windows::handle::Handle;

use std::{collections::HashSet, io};

#[derive(Debug, Default)]
pub struct Message {
    pub payload: Vec<u8>,
    pub objects: Vec<Object>,
}

impl Message {
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            objects: Vec::new(),
        }
    }
    pub fn with_objects(payload: Vec<u8>, objects: Vec<Object>) -> Self {
        Self { payload, objects }
    }
}

#[cfg(target_os = "macos")]
impl From<mach::MachMessage<'_>> for Message {
    fn from(mach_msg: mach::MachMessage<'_>) -> Self {
        Self {
            payload: mach_msg.payload.into(),
            objects: mach_msg
                .descriptors
                .into_iter()
                .map(|r| match r {
                    mach::MachMessageDescriptor::Ool(ool) => Object::Ool(ool),
                    mach::MachMessageDescriptor::Port(port) => Object::Port(port),
                })
                .collect(),
        }
    }
}

#[derive(Debug)]
pub enum Object {
    #[cfg(windows)]
    Handle(Handle),
    #[cfg(target_os = "macos")]
    Port(mach::Port),
    #[cfg(target_os = "macos")]
    Ool(mach::Ool),
}

pub type CredentialValidator = Box<dyn Fn(&Credentials) -> io::Result<()> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub pid: u32,
    pub uid: String,
    pub gid_list: Vec<String>,
    pub is_privileged: bool,
}

#[derive(Default)]
pub struct Policy {
    pub allowed_uid_set: Option<HashSet<String>>,
    pub allowed_gid_set: Option<HashSet<String>>,
    pub require_privileged: bool,
    pub credential_validator: Option<CredentialValidator>,
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn privileged_only() -> Self {
        Self {
            require_privileged: true,
            ..Default::default()
        }
    }

    pub fn with_allowed_uid<I: IntoIterator<Item = S>, S: Into<String>>(mut self, iter: I) -> Self {
        self.allowed_uid_set = Some(iter.into_iter().map(Into::into).collect::<HashSet<_>>());
        self
    }

    pub fn with_allowed_gid<I: IntoIterator<Item = S>, S: Into<String>>(mut self, iter: I) -> Self {
        self.allowed_gid_set = Some(iter.into_iter().map(Into::into).collect::<HashSet<_>>());
        self
    }

    pub fn with_credential_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&Credentials) -> io::Result<()> + Send + Sync + 'static,
    {
        self.credential_validator = Some(Box::new(validator));
        self
    }

    pub fn require_privileged(mut self) -> Self {
        self.require_privileged = true;
        self
    }

    pub fn check(&self, credentials: &Credentials) -> io::Result<()> {
        if self.require_privileged && !credentials.is_privileged {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Process does not have elevated privileges",
            ));
        }

        if let Some(ref allowed_uid_set) = self.allowed_uid_set
            && !allowed_uid_set.contains(&credentials.uid)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("User ID {} not in allowlist", credentials.uid),
            ));
        }

        if let Some(ref allowed_gid_set) = self.allowed_gid_set
            && !credentials
                .gid_list
                .iter()
                .any(|gid| allowed_gid_set.contains(gid))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "No matching group in allowlist",
            ));
        }

        if let Some(ref validator) = self.credential_validator {
            validator(credentials)?;
        }

        Ok(())
    }

    pub fn is_unrestricted(&self) -> bool {
        self.allowed_uid_set.is_none()
            && self.allowed_gid_set.is_none()
            && !self.require_privileged
            && self.credential_validator.is_none()
    }
}

pub struct ServiceDescriptor {
    pub name: String,
    pub policy: Policy,
}

impl ServiceDescriptor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            policy: Policy::default(),
        }
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_allowed_uid<I: IntoIterator<Item = S>, S: Into<String>>(mut self, iter: I) -> Self {
        self.policy.allowed_uid_set =
            Some(iter.into_iter().map(Into::into).collect::<HashSet<_>>());
        self
    }

    pub fn with_allowed_group<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        iter: I,
    ) -> Self {
        self.policy.allowed_gid_set =
            Some(iter.into_iter().map(Into::into).collect::<HashSet<_>>());
        self
    }

    pub fn with_credential_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&Credentials) -> io::Result<()> + Send + Sync + 'static,
    {
        self.policy.credential_validator = Some(Box::new(validator));
        self
    }

    pub fn require_privileged(mut self) -> Self {
        self.policy.require_privileged = true;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

pub trait IntoServiceDescriptor {
    fn into_service_descriptor(self) -> ServiceDescriptor;
}

impl IntoServiceDescriptor for &str {
    fn into_service_descriptor(self) -> ServiceDescriptor {
        ServiceDescriptor::new(self)
    }
}
impl IntoServiceDescriptor for String {
    fn into_service_descriptor(self) -> ServiceDescriptor {
        ServiceDescriptor::new(self)
    }
}
impl IntoServiceDescriptor for &String {
    fn into_service_descriptor(self) -> ServiceDescriptor {
        ServiceDescriptor::new(self.clone())
    }
}
impl IntoServiceDescriptor for ServiceDescriptor {
    fn into_service_descriptor(self) -> ServiceDescriptor {
        self
    }
}



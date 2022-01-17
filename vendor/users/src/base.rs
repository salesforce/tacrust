//! Integration with the C library’s users and groups.
//!
//! This module uses `extern` functions and types from `libc` that integrate
//! with the system’s C library, which integrates with the OS itself to get user
//! and group information. It’s where the “core” user handling is done.
//!
//!
//! ## Name encoding rules
//!
//! Under Unix, usernames and group names are considered to be
//! null-terminated, UTF-8 strings. These are `CString`s in Rust, although in
//! this library, they are just `String` values. Why?
//!
//! The reason is that any user or group values with invalid `CString` data
//! can instead just be assumed to not exist:
//!
//! - If you try to search for a user with a null character in their name,
//!   such a user could not exist anyway—so it’s OK to return `None`.
//! - If the OS returns user information with a null character in a field,
//!   then that field will just be truncated instead, which is valid behaviour
//!   for a `CString`.
//!
//! The downside is that we use `from_utf8_lossy` instead, which has a small
//! runtime penalty when it calculates and scans the length of the string for
//! invalid characters. However, this should not be a problem when dealing with
//! usernames of a few bytes each.
//!
//! In short, if you want to check for null characters in user fields, your
//! best bet is to check for them yourself before passing strings into any
//! functions.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::io::{Result as IoResult, Error as IoError};
use std::os::unix::ffi::OsStrExt;
use std::ptr::read;
use std::sync::Arc;

use libc::{
    c_char,
    uid_t,
    gid_t,
    getpwuid,
    getpwnam,
    getgrgid,
    getgrnam,
    getuid,
    geteuid,
    getgid,
    getegid,
    getgroups,
    getgrouplist,
    c_int,
};
#[cfg(not(target_os = "android"))]
use libc::{
    setpwent,
    getpwent,
    endpwent
};

use libc::passwd as c_passwd;
use libc::group as c_group;

/// Information about a particular user.
#[derive(Clone)]
pub struct User {
    uid: uid_t,
    primary_group: gid_t,
    extras: os::UserExtras,

    /// This user’s name, as an owned `OsString` possibly shared with a cache.
    /// Prefer using the `name()` accessor to using this field, if possible.
    pub name_arc: Arc<OsString>,
}

impl User {

    /// Create a new `User` with the given user ID, name, and primary
    /// group ID, with the rest of the fields filled with dummy values.
    ///
    /// This method does not actually create a new user on the system—it
    /// should only be used for comparing users in tests.
    pub fn new<S: AsRef<OsStr> + ?Sized>(uid: uid_t, name: &S, primary_group: gid_t) -> Self {
        let name_arc = Arc::new(name.into());
        let extras = os::UserExtras::default();
    
        User { uid, name_arc, primary_group, extras }
    }

    /// Returns this user’s ID.
    pub fn uid(&self) -> uid_t {
        self.uid
    }

    /// Returns this user’s name.
    pub fn name(&self) -> &OsStr {
        &**self.name_arc
    }

    /// Returns the ID of this user’s primary group.
    pub fn primary_group_id(&self) -> gid_t {
        self.primary_group
    }

    /// Returns a list of groups this user is a member of
    pub fn groups(&self) -> Option<Vec<Group>> {
        get_user_groups(self.name(), self.primary_group_id())
    }
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.debug_struct("User")
             .field("uid", &self.uid)
             .field("name_arc", &self.name_arc)
             .field("primary_group", &self.primary_group)
             .field("extras", &self.extras)
             .finish()
        }
        else {
            write!(f, "User({}, {})", self.uid(), self.name().to_string_lossy())
        }
    }
}


/// Information about a particular group.
#[derive(Clone)]
pub struct Group {
    gid: gid_t,
    extras: os::GroupExtras,

    /// This group’s name, as an owned `OsString` possibly shared with a cache.
    /// Prefer using the `name()` accessor to using this field, if possible.
    pub name_arc: Arc<OsString>,
}

impl Group {

    /// Create a new `Group` with the given group ID and name, with the
    /// rest of the fields filled in with dummy values.
    ///
    /// This method does not actually create a new group on the system—it
    /// should only be used for comparing groups in tests.
    pub fn new<S: AsRef<OsStr> + ?Sized>(gid: gid_t, name: &S) -> Self {
        let name_arc = Arc::new(name.into());
        let extras = os::GroupExtras::default();
    
        Group { gid, name_arc, extras }
    }

    /// Returns this group’s ID.
    pub fn gid(&self) -> gid_t {
        self.gid
    }

    /// Returns this group’s name.
    pub fn name(&self) -> &OsStr {
        &**self.name_arc
    }
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.debug_struct("Group")
             .field("gid", &self.gid)
             .field("name_arc", &self.name_arc)
             .field("extras", &self.extras)
             .finish()
        }
        else {
            write!(f, "Group({}, {})", self.gid(), self.name().to_string_lossy())
        }
    }
}


/// Reads data from a `*char` field in `c_passwd` or `g_group` into an
/// `OsString` for use in a user or group value.
///
/// The underlying buffer is managed by the C library, not by us, so we *need*
/// to move data out of it before the next user gets read.
unsafe fn from_raw_buf(p: *const c_char) -> OsString {
    OsStr::from_bytes(CStr::from_ptr(p).to_bytes()).to_os_string()
}

unsafe fn passwd_to_user(pointer: *const c_passwd) -> Option<User> {
    if let Some(passwd) = pointer.as_ref().map(|p| read(p)) {
        let name = Arc::new(from_raw_buf(passwd.pw_name));

        Some(User {
            uid:           passwd.pw_uid,
            name_arc:      name,
            primary_group: passwd.pw_gid,
            extras:        os::UserExtras::from_passwd(passwd),
        })
    }
    else {
        None
    }
}

unsafe fn struct_to_group(pointer: *const c_group) -> Option<Group> {
    if let Some(group) = pointer.as_ref().map(|p| read(p)) {
        let name = Arc::new(from_raw_buf(group.gr_name));

        Some(Group {
            gid:       group.gr_gid,
            name_arc:  name,
            extras:    os::GroupExtras::from_struct(group),
        })
    }
    else {
        None
    }
}

/// Expand a list of group members to a vector of strings.
///
/// The list of members is, in true C fashion, a pointer to a pointer of
/// characters, terminated by a null pointer. We check `members[0]`, then
/// `members[1]`, and so on, until that null pointer is reached. It doesn’t
/// specify whether we should expect a null pointer or a pointer to a null
/// pointer, so we check for both here!
unsafe fn members(groups: *mut *mut c_char) -> Vec<OsString> {
    let mut members = Vec::new();

    for i in 0.. {
        let username = groups.offset(i);

        if username.is_null() || (*username).is_null() {
            break;
        }
        else {
            members.push(from_raw_buf(*username));
        }
    }

    members
}


/// Searches for a `User` with the given ID in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_uid(uid: uid_t) -> Option<User> {
    unsafe {
        let passwd = getpwuid(uid);
        passwd_to_user(passwd)
    }
}

/// Searches for a `User` with the given username in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_name<S: AsRef<OsStr> + ?Sized>(username: &S) -> Option<User> {
    if let Ok(username) = CString::new(username.as_ref().as_bytes()) {
        unsafe {
            let passwd = getpwnam(username.as_ptr());
            passwd_to_user(passwd)
        }
    }
    else {
        // The username that was passed in contained a null character.
        // This will *never* find anything, so just return `None`.
        // (I can’t figure out a pleasant way to signal an error here)
        None
    }
}

/// Searches for a `Group` with the given ID in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_gid(gid: gid_t) -> Option<Group> {
    unsafe {
        let group = getgrgid(gid);
        struct_to_group(group)
    }
}

/// Searches for a `Group` with the given group name in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_name<S: AsRef<OsStr> + ?Sized>(group_name: &S) -> Option<Group> {
    if let Ok(group_name) = CString::new(group_name.as_ref().as_bytes()) {
        unsafe {
            let group = getgrnam(group_name.as_ptr());
            struct_to_group(group)
        }
    }
    else {
        // The group name that was passed in contained a null character.
        // This will *never* find anything, so just return `None`.
        // (I can’t figure out a pleasant way to signal an error here)
        None
    }
}

/// Returns the user ID for the user running the process.
pub fn get_current_uid() -> uid_t {
    unsafe { getuid() }
}

/// Returns the username of the user running the process.
pub fn get_current_username() -> Option<OsString> {
    let uid = get_current_uid();
    get_user_by_uid(uid).map(|u| Arc::try_unwrap(u.name_arc).unwrap())
}

/// Returns the user ID for the effective user running the process.
pub fn get_effective_uid() -> uid_t {
    unsafe { geteuid() }
}

/// Returns the username of the effective user running the process.
pub fn get_effective_username() -> Option<OsString> {
    let uid = get_effective_uid();
    get_user_by_uid(uid).map(|u| Arc::try_unwrap(u.name_arc).unwrap())
}

/// Returns the group ID for the user running the process.
pub fn get_current_gid() -> gid_t {
    unsafe { getgid() }
}

/// Returns the groupname of the user running the process.
pub fn get_current_groupname() -> Option<OsString> {
    let gid = get_current_gid();
    get_group_by_gid(gid).map(|g| Arc::try_unwrap(g.name_arc).unwrap())
}

/// Returns the group ID for the effective user running the process.
pub fn get_effective_gid() -> gid_t {
    unsafe { getegid() }
}

/// Returns the groupname of the effective user running the process.
pub fn get_effective_groupname() -> Option<OsString> {
    let gid = get_effective_gid();
    get_group_by_gid(gid).map(|g| Arc::try_unwrap(g.name_arc).unwrap())
}

/// Returns the group access list for the current process.
pub fn group_access_list() -> IoResult<Vec<Group>> {
    let mut buff: Vec<gid_t> = vec![0; 1024];
    
    let res = unsafe {
        getgroups(1024, buff.as_mut_ptr())
    };

    if res < 0 {
        Err(IoError::last_os_error())
    }
    else {
        let mut groups = buff.into_iter()
                                     .filter_map(|i| get_group_by_gid(i))
                                     .collect::<Vec<_>>();
        groups.dedup_by_key(|i| i.gid());
        Ok(groups)
    }
}

/// Returns groups for a provided user name and primary group id
pub fn get_user_groups<S: AsRef<OsStr> + ?Sized>(username: &S, gid: gid_t) -> Option<Vec<Group>> {
    // MacOS uses i32 instead of gid_t in getgrouplist for unknown reasons
    #[cfg(all(unix, target_os="macos"))]
    let mut buff: Vec<i32> = vec![0; 1024];
    #[cfg(all(unix, not(target_os="macos")))]
    let mut buff: Vec<gid_t> = vec![0; 1024];

    let name = CString::new(username.as_ref().as_bytes()).unwrap();
    let mut count = buff.len() as c_int;

    // MacOS uses i32 instead of gid_t in getgrouplist for unknown reasons
    #[cfg(all(unix, target_os="macos"))]
    let res = unsafe {
        getgrouplist(name.as_ptr(), gid as i32, buff.as_mut_ptr(), &mut count)
    };
    
    #[cfg(all(unix, not(target_os="macos")))]
    let res = unsafe {
        getgrouplist(name.as_ptr(), gid, buff.as_mut_ptr(), &mut count)
    };

    if res < 0 {
        None
    }
    else {
        buff.dedup();
        buff.into_iter()
            .filter_map(|i| get_group_by_gid(i as gid_t))
            .collect::<Vec<_>>()
            .into()
    }
}



/// An iterator over every user present on the system.
struct AllUsers;

/// Creates a new iterator over every user present on the system.
///
/// ## Unsafety
///
/// This constructor is marked as `unsafe`, which is odd for a crate
/// that’s meant to be a safe interface. It *has* to be unsafe because
/// we cannot guarantee that the underlying C functions,
/// `getpwent`/`setpwent`/`endpwent` that iterate over the system’s
/// `passwd` entries, are called in a thread-safe manner.
///
/// These functions [modify a global
/// state](http://man7.org/linux/man-pages/man3/getpwent.3.html#ATTRIBUTES),
/// and if any are used at the same time, the state could be reset,
/// resulting in a data race. We cannot even place it behind an internal
/// `Mutex`, as there is nothing stopping another `extern` function
/// definition from calling it!
///
/// So to iterate all users, construct the iterator inside an `unsafe`
/// block, then make sure to not make a new instance of it until
/// iteration is over.
pub unsafe fn all_users() -> impl Iterator<Item=User> {
    #[cfg(not(target_os = "android"))]
    setpwent();
    AllUsers
}

impl Drop for AllUsers {
    fn drop(&mut self) {
        #[cfg(not(target_os = "android"))]
        unsafe { endpwent() };
    }
}

impl Iterator for AllUsers {
    type Item = User;

    #[cfg(target_os = "android")]
    fn next(&mut self) -> Option<User> {
        None
    }
    #[cfg(not(target_os = "android"))]
    fn next(&mut self) -> Option<User> {
        unsafe { passwd_to_user(getpwent()) }
    }
}



/// OS-specific extensions to users and groups.
///
/// Every OS has a different idea of what data a user or a group comes with.
/// Although they all provide a *username*, some OS’ users have an *actual name*
/// too, or a set of permissions or directories or timestamps associated with
/// them.
///
/// This module provides extension traits for users and groups that allow
/// implementors of this library to access this data *as long as a trait is
/// available*, which requires the OS they’re using to support this data.
///
/// It’s the same method taken by `Metadata` in the standard Rust library,
/// which has a few cross-platform fields and many more OS-specific fields:
/// traits in `std::os` provides access to any data that is not guaranteed to
/// be there in the actual struct.
pub mod os {

    /// Extensions to users and groups for Unix platforms.
    ///
    /// Although the `passwd` struct is common among Unix systems, its actual
    /// format can vary. See the definitions in the `base` module to check which
    /// fields are actually present.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd", target_os = "solaris"))]
    pub mod unix {
        use std::ffi::{OsStr, OsString};
        use std::path::{Path, PathBuf};

        use super::super::{c_passwd, c_group, members, from_raw_buf, Group};

        /// Unix-specific extensions for `User`s.
        pub trait UserExt {

            /// Returns a path to this user’s home directory.
            fn home_dir(&self) -> &Path;

            /// Sets this user value’s home directory to the given string.
            /// Can be used to construct test users, which by default come with a
            /// dummy home directory string.
            fn with_home_dir<S: AsRef<OsStr> + ?Sized>(self, home_dir: &S) -> Self;

            /// Returns a path to this user’s shell.
            fn shell(&self) -> &Path;

            /// Sets this user’s shell path to the given string.
            /// Can be used to construct test users, which by default come with a
            /// dummy shell field.
            fn with_shell<S: AsRef<OsStr> + ?Sized>(self, shell: &S) -> Self;

            /// Returns the user’s encrypted password.
            fn password(&self) -> &OsStr;

            /// Sets this user’s password to the given string.
            /// Can be used to construct tests users, which by default come with a
            /// dummy password field.
            fn with_password<S: AsRef<OsStr> + ?Sized>(self, password: &S) -> Self;
        }

        /// Unix-specific extensions for `Group`s.
        pub trait GroupExt {

            /// Returns a slice of the list of users that are in this group as
            /// their non-primary group.
            fn members(&self) -> &[OsString];

            /// Adds a new member to this group.
            fn add_member<S: AsRef<OsStr> + ?Sized>(self, name: &S) -> Self;
        }

        /// Unix-specific fields for `User`s.
        #[derive(Clone, Debug)]
        pub struct UserExtras {

            /// The path to the user’s home directory.
            pub home_dir: PathBuf,

            /// The path to the user’s shell.
            pub shell: PathBuf,

            /// The user’s encrypted password.
            pub password: OsString,
        }

        impl Default for UserExtras {
            fn default() -> Self {
                UserExtras {
                    home_dir: "/var/empty".into(),
                    shell:    "/bin/false".into(),
                    password: "*".into(),
                }
            }
        }

        impl UserExtras {
            /// Extract the OS-specific fields from the C `passwd` struct that
            /// we just read.
            pub unsafe fn from_passwd(passwd: c_passwd) -> Self {
                #[cfg(target_os = "android")]
                {
                    Default::default()
                }
                #[cfg(not(target_os = "android"))]
                {
                    let home_dir = from_raw_buf(passwd.pw_dir).into();
                    let shell    = from_raw_buf(passwd.pw_shell).into();
                    let password = from_raw_buf(passwd.pw_passwd);

                    UserExtras { home_dir, shell, password }
                }
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "solaris"))]
        use super::super::User;

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "solaris"))]
        impl UserExt for User {
            fn home_dir(&self) -> &Path {
                Path::new(&self.extras.home_dir)
            }

            fn with_home_dir<S: AsRef<OsStr> + ?Sized>(mut self, home_dir: &S) -> Self {
                self.extras.home_dir = home_dir.into();
                self
            }

            fn shell(&self) -> &Path {
                Path::new(&self.extras.shell)
            }

            fn with_shell<S: AsRef<OsStr> + ?Sized>(mut self, shell: &S) -> Self {
                self.extras.shell = shell.into();
                self
            }

            fn password(&self) -> &OsStr {
                &self.extras.password
            }

            fn with_password<S: AsRef<OsStr> + ?Sized>(mut self, password: &S) -> Self {
                self.extras.password = password.into();
                self
            }
        }

        /// Unix-specific fields for `Group`s.
        #[derive(Clone, Default, Debug)]
        pub struct GroupExtras {

            /// Vector of usernames that are members of this group.
            pub members: Vec<OsString>,
        }

        impl GroupExtras {
            /// Extract the OS-specific fields from the C `group` struct that
            /// we just read.
            pub unsafe fn from_struct(group: c_group) -> Self {
                GroupExtras { members: members(group.gr_mem) }
            }
        }

        impl GroupExt for Group {
            fn members(&self) -> &[OsString] {
                &*self.extras.members
            }

            fn add_member<S: AsRef<OsStr> + ?Sized>(mut self, member: &S) -> Self {
                self.extras.members.push(member.into());
                self
            }
        }
    }

    /// Extensions to users and groups for BSD platforms.
    ///
    /// These platforms have `change` and `expire` fields in their `passwd`
    /// C structs.
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd"))]
    pub mod bsd {
        use std::ffi::OsStr;
        use std::path::Path;
        use libc::time_t;
        use super::super::{c_passwd, User};

        /// BSD-specific fields for `User`s.
        #[derive(Clone, Debug)]
        pub struct UserExtras {

            /// Fields specific to Unix, rather than just BSD. (This struct is
            /// a superset, so it has to have all the other fields in it, too).
            pub extras: super::unix::UserExtras,

            /// Password change time.
            pub change: time_t,

            /// Password expiry time.
            pub expire: time_t,
        }

        impl UserExtras {
            /// Extract the OS-specific fields from the C `passwd` struct that
            /// we just read.
            pub unsafe fn from_passwd(passwd: c_passwd) -> Self {
                UserExtras {
                    change: passwd.pw_change,
                    expire: passwd.pw_expire,
                    extras: super::unix::UserExtras::from_passwd(passwd),
                }
            }
        }

        impl super::unix::UserExt for User {
            fn home_dir(&self) -> &Path {
                Path::new(&self.extras.extras.home_dir)
            }

            fn with_home_dir<S: AsRef<OsStr> + ?Sized>(mut self, home_dir: &S) -> Self {
                self.extras.extras.home_dir = home_dir.into();
                self
            }

            fn shell(&self) -> &Path {
                Path::new(&self.extras.extras.shell)
            }

            fn with_shell<S: AsRef<OsStr> + ?Sized>(mut self, shell: &S) -> Self {
                self.extras.extras.shell = shell.into();
                self
            }

            fn password(&self) -> &OsStr {
                &self.extras.extras.password
            }

            fn with_password<S: AsRef<OsStr> + ?Sized>(mut self, password: &S) -> Self {
                self.extras.extras.password = password.into();
                self
            }
        }

        /// BSD-specific accessors for `User`s.
        pub trait UserExt {

            /// Returns this user’s password change timestamp.
            fn password_change_time(&self) -> time_t;

            /// Returns this user’s password expiry timestamp.
            fn password_expire_time(&self) -> time_t;
        }

        impl UserExt for User {
            fn password_change_time(&self) -> time_t {
                self.extras.change
            }

            fn password_expire_time(&self) -> time_t {
                self.extras.expire
            }
        }

        impl Default for UserExtras {
            fn default() -> Self {
                UserExtras {
                    extras: super::unix::UserExtras::default(),
                    change: 0,
                    expire: 0,
                }
            }
        }
    }

    /// Any extra fields on a `User` specific to the current platform.
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd"))]
    pub type UserExtras = bsd::UserExtras;

    /// Any extra fields on a `User` specific to the current platform.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "solaris"))]
    pub type UserExtras = unix::UserExtras;

    /// Any extra fields on a `Group` specific to the current platform.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd", target_os = "solaris"))]
    pub type GroupExtras = unix::GroupExtras;
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn uid() {
        get_current_uid();
    }

    #[test]
    fn username() {
        let uid = get_current_uid();
        assert_eq!(&*get_current_username().unwrap(), &*get_user_by_uid(uid).unwrap().name());
    }

    #[test]
    fn uid_for_username() {
        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        assert_eq!(user.uid, uid);
    }

    #[test]
    fn username_for_uid_for_username() {
        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        let user2 = get_user_by_uid(user.uid).unwrap();
        assert_eq!(user2.uid, uid);
    }

    #[test]
    fn user_info() {
        use base::os::unix::UserExt;

        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        // Not a real test but can be used to verify correct results
        // Use with --nocapture on test executable to show output
        println!("HOME={:?}, SHELL={:?}, PASSWD={:?}",
            user.home_dir(), user.shell(), user.password());
    }

    #[test]
    fn user_by_name() {
        // We cannot really test for arbitrary user as they might not exist on the machine
        // Instead the name of the current user is used
        let name = get_current_username().unwrap();
        let user_by_name = get_user_by_name(&name);
        assert!(user_by_name.is_some());
        assert_eq!(user_by_name.unwrap().name(), &*name);

        // User names containing '\0' cannot be used (for now)
        let user = get_user_by_name("user\0");
        assert!(user.is_none());
    }

    #[test]
    fn user_get_groups() {
        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        let groups = user.groups().unwrap();
        println!("Groups: {:?}", groups);
        assert!(groups.len() > 0);
    }

    #[test]
    fn group_by_name() {
        // We cannot really test for arbitrary groups as they might not exist on the machine
        // Instead the primary group of the current user is used
        let cur_uid = get_current_uid();
        let cur_user = get_user_by_uid(cur_uid).unwrap();
        let cur_group = get_group_by_gid(cur_user.primary_group).unwrap();
        let group_by_name = get_group_by_name(&cur_group.name());

        assert!(group_by_name.is_some());
        assert_eq!(group_by_name.unwrap().name(), cur_group.name());

        // Group names containing '\0' cannot be used (for now)
        let group = get_group_by_name("users\0");
        assert!(group.is_none());
    }
}

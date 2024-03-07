/*
 * Copyright 2024 Oxide Computer Company
 */

use std::{
    cmp::Ordering,
    ffi::CStr,
    os::fd::{AsRawFd, BorrowedFd},
};

use libc::{c_char, c_int, gid_t, pid_t, projid_t, ucred_t, uid_t, zoneid_t};

/*
 * These routines are currently not exposed through the libc crate:
 */
extern "C" {
    fn door_ucred(info: *mut *mut ucred_t) -> c_int;
    fn getzoneid() -> zoneid_t;
}

const P_MYID: pid_t = -1;
const GLOBAL_ZONEID: zoneid_t = 0;

pub struct UCred {
    uc: *mut libc::ucred_t,
}

impl UCred {
    /**
     * Use ucred_get(3C) with the P_MYID argument to get credentials for the
     * current process.
     */
    pub fn for_self() -> std::io::Result<UCred> {
        Self::for_pid(P_MYID)
    }

    /**
     * Use ucred_get(3C) with get credentials for the nominated process.
     */
    pub fn for_pid(pid: libc::pid_t) -> std::io::Result<UCred> {
        let uc = unsafe { libc::ucred_get(pid) };
        if uc.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(UCred { uc })
        }
    }

    /**
     * Use getpeerucred(3C) to obtain the credentials of the peer endpoint of a
     * connection-oriented socket (SOCK_STREAM) or stream file descriptor.
     */
    pub fn for_socket(fd: BorrowedFd) -> std::io::Result<UCred> {
        let mut uc: *mut libc::ucred_t = std::ptr::null_mut();
        let r = unsafe { libc::getpeerucred(fd.as_raw_fd(), &mut uc) };
        if r == 0 {
            assert!(!uc.is_null());
            Ok(UCred { uc })
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /**
     * Use door_ucred(3C) to obtain the credentials of the client responsible
     * for the current door invocation.  It only makes sense to call this
     * routine from a door call service procedure that is actively serving a
     * door call.
     */
    pub fn for_door_call() -> std::io::Result<UCred> {
        let mut uc: *mut libc::ucred_t = std::ptr::null_mut();
        let r = unsafe { door_ucred(&mut uc) };
        if r == 0 {
            assert!(!uc.is_null());
            Ok(UCred { uc })
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn common_get_s<T: PartialEq<i32>>(
        &self,
        func: unsafe extern "C" fn(*const ucred_t) -> T,
    ) -> Option<T> {
        let id = unsafe { func(self.uc) };
        if id == -1 {
            None
        } else {
            Some(id)
        }
    }

    fn common_get_u<T: PartialEq<u32>>(
        &self,
        func: unsafe extern "C" fn(*const ucred_t) -> T,
    ) -> Option<T> {
        let id = unsafe { func(self.uc) };
        if id == u32::MAX {
            None
        } else {
            Some(id)
        }
    }

    /**
     * Return the process ID, if the credential contains one.
     */
    pub fn pid(&self) -> Option<pid_t> {
        self.common_get_s(libc::ucred_getpid)
    }

    /**
     * Does this credential come from the current process?
     */
    pub fn is_same_process(&self) -> bool {
        self.pid()
            .map(|otherpid| std::process::id() == otherpid.try_into().unwrap())
            .unwrap_or(false)
    }

    /**
     * Return the project ID of the process, if the credential contains one.
     */
    pub fn project(&self) -> Option<projid_t> {
        self.common_get_s(libc::ucred_getprojid)
    }

    /**
     * Return the zone ID of the zone in which the process resides, if the
     * credential contains one.
     */
    pub fn zoneid(&self) -> Option<zoneid_t> {
        self.common_get_s(libc::ucred_getzoneid)
    }

    /**
     * Does this credential come from the same zone as the current process?
     */
    pub fn is_same_zone(&self) -> std::io::Result<bool> {
        let zid = unsafe { getzoneid() };
        if zid < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(self.zoneid().map(|otherzid| otherzid == zid).unwrap_or(false))
    }

    /**
     * Does this credential come from a process in the global zone?
     */
    pub fn is_global_zone(&self) -> bool {
        self.zoneid().map(|otherzid| otherzid == GLOBAL_ZONEID).unwrap_or(false)
    }

    /**
     * Return the effective user ID for the user credential, if it contains one.
     */
    pub fn euid(&self) -> Option<uid_t> {
        self.common_get_u(libc::ucred_geteuid)
    }

    /**
     * Resolve the effective user ID to a username and return it.
     *
     * NOTE: Each zone has its own independent passwd(5) database.  If this
     * credential represents a user in another zone, it may not be correct to
     * resolve it to a name using the local database unless those databases are
     * synchronised through some operational process.
     */
    pub fn euser(&self) -> std::io::Result<Option<User>> {
        self.euid().map(uid_to_user).transpose().map(Option::flatten)
    }

    /**
     * Return the real user ID for the user credential, if it contains one.
     */
    pub fn ruid(&self) -> Option<uid_t> {
        self.common_get_u(libc::ucred_getruid)
    }

    /**
     * Resolve the real user ID to a username and return it.
     *
     * NOTE: Each zone has its own independent passwd(5) database.  If this
     * credential represents a user in another zone, it may not be correct to
     * resolve it to a name using the local database unless those databases are
     * synchronised through some operational process.
     */
    pub fn ruser(&self) -> std::io::Result<Option<User>> {
        self.ruid().map(uid_to_user).transpose().map(Option::flatten)
    }

    /**
     * Return the saved user ID for the user credential, if it contains one.
     */
    pub fn suid(&self) -> Option<uid_t> {
        self.common_get_u(libc::ucred_getsuid)
    }

    /**
     * Resolve the saved user ID to a username and return it.
     *
     * NOTE: Each zone has its own independent passwd(5) database.  If this
     * credential represents a user in another zone, it may not be correct to
     * resolve it to a name using the local database unless those databases are
     * synchronised through some operational process.
     */
    pub fn suser(&self) -> std::io::Result<Option<User>> {
        self.suid().map(uid_to_user).transpose().map(Option::flatten)
    }

    /**
     * Return the effective user ID for the user credential, if it contains one.
     */
    pub fn egid(&self) -> Option<gid_t> {
        self.common_get_u(libc::ucred_getegid)
    }

    /**
     * Resolve the effective group ID to a group name and return it.
     *
     * NOTE: Each zone has its own independent group(5) database.  If this
     * credential represents a group in another zone, it may not be correct to
     * resolve it to a name using the local database unless those databases are
     * synchronised through some operational process.
     */
    pub fn egroup(&self) -> std::io::Result<Option<Group>> {
        self.egid().map(gid_to_group).transpose().map(Option::flatten)
    }

    /**
     * Return the real user ID for the user credential, if it contains one.
     */
    pub fn rgid(&self) -> Option<gid_t> {
        self.common_get_u(libc::ucred_getrgid)
    }

    /**
     * Resolve the real group ID to a group name and return it.
     *
     * NOTE: Each zone has its own independent group(5) database.  If this
     * credential represents a group in another zone, it may not be correct to
     * resolve it to a name using the local database unless those databases are
     * synchronised through some operational process.
     */
    pub fn rgroup(&self) -> std::io::Result<Option<Group>> {
        self.rgid().map(gid_to_group).transpose().map(Option::flatten)
    }

    /**
     * Return the saved user ID for the user credential, if it contains one.
     */
    pub fn sgid(&self) -> Option<gid_t> {
        self.common_get_u(libc::ucred_getsgid)
    }

    /**
     * Resolve the saved group ID to a group name and return it.
     *
     * NOTE: Each zone has its own independent group(5) database.  If this
     * credential represents a group in another zone, it may not be correct to
     * resolve it to a name using the local database unless those databases are
     * synchronised through some operational process.
     */
    pub fn sgroup(&self) -> std::io::Result<Option<Group>> {
        self.sgid().map(gid_to_group).transpose().map(Option::flatten)
    }

    pub fn groups(&self) -> Option<&[gid_t]> {
        /*
         * According to ucred(3C), "the returned group list is valid until
         * ucred_free() is called on the user credential given as argument",
         * so we can return a borrowed slice here.
         */
        let mut groups: *const gid_t = std::ptr::null();
        let ngroups = unsafe { libc::ucred_getgroups(self.uc, &mut groups) };
        match ngroups.cmp(&0) {
            Ordering::Less => None,
            Ordering::Equal => Some(&[]),
            Ordering::Greater => {
                assert!(!groups.is_null());
                Some(unsafe {
                    std::slice::from_raw_parts(
                        groups,
                        ngroups.try_into().unwrap(),
                    )
                })
            }
        }
    }
}

impl Drop for UCred {
    fn drop(&mut self) {
        assert!(!self.uc.is_null());
        unsafe { libc::ucred_free(self.uc) };
    }
}

#[derive(Debug)]
pub struct User {
    pub uid: uid_t,
    pub gid: gid_t,
    pub name: String,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

pub fn uid_to_user(uid: uid_t) -> std::io::Result<Option<User>> {
    unsafe { *libc::___errno() = 0 };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        let e = unsafe { *libc::___errno() };
        if e == 0 {
            Ok(None)
        } else {
            Err(std::io::Error::from_raw_os_error(e))
        }
    } else {
        let pw = unsafe { &*pw };
        assert_eq!(pw.pw_uid, uid);

        Ok(Some(User {
            uid: pw.pw_uid,
            gid: pw.pw_gid,
            name: cstr_to_string(pw.pw_name)?,
            gecos: cstr_to_string(pw.pw_gecos)?,
            dir: cstr_to_string(pw.pw_dir)?,
            shell: cstr_to_string(pw.pw_shell)?,
        }))
    }
}

#[derive(Debug)]
pub struct Group {
    pub gid: gid_t,
    pub name: String,
}

pub fn gid_to_group(gid: gid_t) -> std::io::Result<Option<Group>> {
    unsafe { *libc::___errno() = 0 };
    let gr = unsafe { libc::getgrgid(gid) };
    if gr.is_null() {
        let e = unsafe { *libc::___errno() };
        if e == 0 {
            Ok(None)
        } else {
            Err(std::io::Error::from_raw_os_error(e))
        }
    } else {
        let gr = unsafe { &*gr };
        assert_eq!(gr.gr_gid, gid);

        Ok(Some(Group { gid: gr.gr_gid, name: cstr_to_string(gr.gr_name)? }))
    }
}

fn cstr_to_string(c: *const c_char) -> std::io::Result<String> {
    if c.is_null() {
        Ok("".into())
    } else {
        let c = unsafe { CStr::from_ptr(c) };
        c.to_str().map(str::to_string).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }
}

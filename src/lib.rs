// #![feature(duration_as_u128)]
#![deny(warnings)]
#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;
extern crate nix;
extern crate libc;
extern crate oci;
extern crate prctl;
extern crate railcar;
#[macro_use]
extern crate scopeguard;
extern crate lazy_static;

use nix::errno::Errno;
use nix::unistd::{chdir, getpid, sethostname};
use nix::unistd::{close, dup2, setsid, write, Pid};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::socket::{ControlMessage, MsgFlags};

use railcar::{selinux, cgroups, errors, do_exec, DEFAULT_DEVICES, NAMESPACES};

// use std::time::{Duration, SystemTime};
// use std::sync::mpsc;
// use std::thread::JoinHandle;
// use std::os::unix::thread::JoinHandleExt;

use lazy_static::initialize;
use railcar::{signals, Result, Error};
use nix::sys::signal::Signal;
use railcar::logger;
use nix::sys::socket::{socket, bind, AddressFamily, SockAddr, SockFlag, SockType, UnixAddr};
use railcar::fork_first;
use nix::unistd::Uid;
use nix::unistd::Gid;
use railcar::mounts;
use nix::sys::socket::sendmsg;
use railcar::capabilities;
use railcar::seccomp;
use nix::sys::socket::listen;
use nix::sys::socket::accept;
use std::os::unix::io::RawFd;
use railcar::do_init;
use railcar::fork_final_child;
use railcar::wait_for_pipe_zero;
use railcar::setid;
use railcar::fork_enter_pid;
use railcar::set_sysctl;
use railcar::reopen_dev_null;
use railcar::load_console_sockets;
use errors::*;
use nix::unistd::unlink;
use r_judge::pseudo_tty;

// only show backtrace in debug mode
#[cfg(not(debug_assertions))]
pub fn print_backtrace(_: &Error) {}

#[cfg(debug_assertions)]
pub fn print_backtrace(e: &Error) {
    match e.backtrace() {
        Some(backtrace) => error!("{:?}", backtrace),
        None => error!("to view backtrace, use RUST_BACKTRACE=1"),
    }
}

pub fn pseudo_tty() -> (RawFd, RawFd, RawFd) {
    let tsocket = "trigger-socket";
    let tmpfd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    // NOTE(vish): we might overwrite fds 0, 1, 2 with the console
    //             so make sure tsocketfd is a high fd that won't
    //             get overwritten
    debug!("overwrite fds 0, 1, 2");
    dup2(tmpfd, TSOCKETFD).chain_err(|| "could not dup tsocketfd")?;
    close(tmpfd).chain_err(|| "could not close tsocket tmpfd")?;
    let tsocketfd = TSOCKETFD;
    unlink(tsocket)?;
    bind(tsocketfd, &SockAddr::Unix(UnixAddr::new(&*tsocket)?))?;
    let (csocketfd, consolefd) = load_console_sockets()?;
    (csocketfd, consolefd, tsocketfd)
}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

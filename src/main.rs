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

use railcar::{selinux, cgroups, do_exec, DEFAULT_DEVICES, NAMESPACES};

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

const CONFIG: &'static str = "config.json";
const INIT_PID: &'static str = "init.pid";
const PROCESS_PID: &'static str = "process.pid";
const TSOCKETFD: RawFd = 9;


fn safe_run_container(id: &str, mut init: bool, mut init_only: bool, args: &[String]) -> Result<Pid> {
    let pid = getpid();
    match run_container(id, init, init_only, args) {
        Err(e) => {
            // if we are the top level thread, kill all children
            if pid == getpid() {
                signals::signal_children(Signal::SIGTERM).unwrap();
            }
            Err(e)
        }
        Ok(child_pid) => Ok(child_pid),
    }
}

fn run_container(id: &str, mut init: bool, mut init_only: bool, args: &[String]) -> Result<Pid> {
    debug!("set dumpable");
    if let Err(e) = prctl::set_dumpable(false) {
        bail!("set dumpable returned {}", e);
    };

    debug!("set selinux label");
    let selinux_label = "";
    if let Err(e) = selinux::setexeccon(selinux_label) {
        warn!(
            "could not set label to {}: {}",
            selinux_label, e
        );
    };

    debug!("initialize static variables before forking");
    // initialize static variables before forking
    initialize(&DEFAULT_DEVICES);
    initialize(&NAMESPACES);
    cgroups::init();

    debug!("collect namespaces");
    // collect namespaces
    let mut cf = CloneFlags::empty();
    let mut to_enter = Vec::new();
    let mut enter_pid = false;
    for ns in &linux.namespaces {
        let space = CloneFlags::from_bits_truncate(ns.typ as i32);
        if space == CloneFlags::CLONE_NEWPID {
            enter_pid = true;
        }
        cf |= space;
    }

    if !enter_pid {
        init = false;
        init_only = false;
    }
    let cpath = format!{"/{}", id};

    let mut bind_devices = false;
    let mut userns = false;
    let rlimits = vec!(
        oci::LinuxRlimit{
            typ: oci::LinuxRlimitType::RLIMIT_NOFILE,
            hard: 1024,
            soft: 1024
        }
    );
    // fork for userns and cgroups
    if cf.contains(CloneFlags::CLONE_NEWUSER) {
        bind_devices = true;
        userns = true;
    }

    if let Err(e) = prctl::set_child_subreaper(true) {
        bail!(format!("set subreaper returned {}", e));
    };

    let (child_pid, wfd) = fork_first(
        id, init_pid, enter_pid, init_only, daemonize, userns, &linux, &rlimits,
        &cpath,
    )?;

    // parent returns child pid and exits
    if child_pid != Pid::from_raw(-1) {
        return Ok(child_pid);
    }

    let mut mount_fd = -1;
    // enter path namespaces
    for &(space, fd) in &to_enter {
        if space == CloneFlags::CLONE_NEWNS {
            // enter mount ns last
            mount_fd = fd;
            continue;
        }
        setns(fd, space).chain_err(|| format!("failed to enter {:?}", space))?;
        close(fd)?;
        if space == CloneFlags::CLONE_NEWUSER {
            setid(Uid::from_raw(0), Gid::from_raw(0))
                .chain_err(|| "failed to setid")?;
            bind_devices = true;
        }
    }

    // unshare other ns
    let chain = || format!("failed to unshare {:?}", cf);
    unshare(cf & !CloneFlags::CLONE_NEWUSER).chain_err(chain)?;


    if enter_pid {
        fork_enter_pid(init, daemonize)?;
    };

    if cf.contains(CloneFlags::CLONE_NEWUTS) {
        sethostname("rJudge")?;
    }

    let mounts = oci::Mount::default();
    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::init_rootfs_without_spec(Some(&linux), rootfs, &cpath, &mounts, bind_devices)
            .chain_err(|| "failed to init rootfs")?;
    }

    if !init_only {
        // notify first parent that it can continue
        debug!("writing zero to pipe to trigger prestart");
        let data: &[u8] = &[0];
        write(wfd, data).chain_err(|| "failed to write zero")?;
    }

    if mount_fd != -1 {
        setns(mount_fd, CloneFlags::CLONE_NEWNS).chain_err(|| {
            "failed to enter CloneFlags::CLONE_NEWNS".to_string()
        })?;
        close(mount_fd)?;
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::pivot_rootfs(&*rootfs).chain_err(|| "failed to pivot rootfs")?;

        // only set sysctls in newns
        for (key, value) in &linux.sysctl {
            set_sysctl(key, value)?;
        }

        // NOTE: apparently criu has problems if pointing to an fd outside
        //       the filesystem namespace.
        reopen_dev_null()?;
    }

    if csocketfd != -1 {
        let mut slave: libc::c_int = unsafe { std::mem::uninitialized() };
        let mut master: libc::c_int = unsafe { std::mem::uninitialized() };
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        Errno::result(ret).chain_err(|| "could not openpty")?;
        defer!(close(master).unwrap());
        let data: &[u8] = b"/dev/ptmx";
        let iov = [nix::sys::uio::IoVec::from_slice(data)];
        //let fds = [master.as_raw_fd()];
        let fds = [master];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg(csocketfd, &iov, &[cmsg], MsgFlags::empty(), None)?;
        consolefd = slave;
        close(csocketfd).chain_err(|| "could not close csocketfd")?;
    }

    if consolefd != -1 {
        setsid()?;
        if unsafe { libc::ioctl(consolefd, libc::TIOCSCTTY) } < 0 {
            warn!("could not TIOCSCTTY");
        };
        dup2(consolefd, 0).chain_err(|| "could not dup tty to stdin")?;
        dup2(consolefd, 1).chain_err(|| "could not dup tty to stdout")?;
        dup2(consolefd, 2).chain_err(|| "could not dup tty to stderr")?;

        if consolefd > 2 {
            close(consolefd).chain_err(|| "could not close consolefd")?;
        }

        // NOTE: we may need to fix up the mount of /dev/console
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::finish_rootfs_without_spec(&mounts).chain_err(|| "failed to finish rootfs")?;
    }

    // change to specified working directory
    chdir(&*"/")?;

    debug!("setting ids");

    // set uid/gid/groups
    let uid = Uid::from_raw(0);
    let gid = Gid::from_raw(0);
    setid(uid, gid)?;

    // NOTE: if we want init to pass signals to other processes, we may want
    //       to hold on to cap kill until after the final fork.
    let noNewPrivileges = true;
    let capabilities = oci::LinuxCapabilities::default();
    let seccomp = None;
    if noNewPrivileges {
        if let Err(e) = prctl::set_no_new_privileges(true) {
            bail!(format!("set no_new_privs returned {}", e));
        };
        // drop privileges
        capabilities::drop_privileges(&capabilities)?;
        if let Some(ref seccomp) = seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
    } else {
        // NOTE: if we have not set no new priviliges, we must set up seccomp
        //       before capset, which will error if seccomp blocks it
        if let Some(ref seccomp) = seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
        // drop privileges
        capabilities::drop_privileges(&capabilities)?;
    }

    // notify first parent that it can continue
    debug!("writing zero to pipe to trigger poststart");
    let data: &[u8] = &[0];
    write(wfd, data).chain_err(|| "failed to write zero")?;

    if init {
        if init_only && tsocketfd == -1 {
            do_init(wfd, daemonize)?;
        } else {
            fork_final_child(wfd, tsocketfd, daemonize)?;
        }
    }

    // we nolonger need wfd, so close it
    close(wfd).chain_err(|| "could not close wfd")?;

    // wait for trigger
    if tsocketfd != -1 {
        listen(tsocketfd, 1)?;
        let fd = accept(tsocketfd)?;
        wait_for_pipe_zero(fd, -1)?;
        close(fd).chain_err(|| "could not close accept fd")?;
        close(tsocketfd).chain_err(|| "could not close trigger fd")?;
    }

    do_exec(args[0].as_ref(), args, env)?;
    Ok(Pid::from_raw(-1))
}


fn run() -> Result<Pid> {
    let id = "rJudge";
    let rootfs: &str = "/root/rootfs";
    let init_pid: Pid = Pid::from_raw(-1);
    let mut init: bool = true;
    let mut init_only: bool = true;

    let interactive: bool = false;
    let tty: bool = false;
    let daemonize: bool = false;

    let args= &["sh".to_string()];
    let env= &[
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "TERM=xterm".to_string()
    ];

    let linux = oci::Linux::default();

    debug!("needed a pseudo-TTY? {}", tty);
    let (csocketfd, consolefd, tsocketfd) = if tty {
        pseudo_tty()
    } else {
        (-1, -1, -1)
    };

    let child_pid = safe_run_container(id, init, init_only, args);

    Ok(Pid::from_raw(-1))
}

pub fn safe_run() -> Result<Pid> {
    let pid = getpid();
    match run() {
        Err(e) => {
            // if we are the top level thread, kill all children
            if pid == getpid() {
                signals::signal_children(Signal::SIGTERM).unwrap();
            }
            Err(e)
        }
        Ok(child_pid) => Ok(child_pid),
    }
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    let _ = log::set_logger(&logger::SIMPLE_LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Debug));

    if let Err(ref e) = run() {
        error!("{}", e);

        for e in e.iter().skip(1) {
            error!("caused by: {}", e);
        }

        print_backtrace(e);
        ::std::process::exit(1);
    }
    ::std::process::exit(0);
}
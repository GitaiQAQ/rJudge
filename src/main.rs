#![feature(duration_as_u128)]
#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;
extern crate nix;
extern crate oci;
extern crate prctl;
extern crate railcar;
extern crate lazy_static;

use nix::unistd::{chdir, execvp, getpid, sethostname, setresgid, setresuid};
use nix::unistd::{close, dup2, fork, pipe2, read, setsid, write, ForkResult, Pid};
use nix::sched::{setns, unshare, CloneFlags};

use std::fs::{canonicalize, create_dir, create_dir_all, remove_dir_all, File};

use railcar::{selinux, cgroups, errors, do_exec, DEFAULT_DEVICES, NAMESPACES};
use nix::fcntl::open;

use std::{thread, env};
use std::time::{Duration, SystemTime};
use std::sync::mpsc;
use std::thread::JoinHandle;

use lazy_static::initialize;
use railcar::{signals, Result, Error};
use nix::sys::signal::Signal;
use railcar::logger;


// only show backtrace in debug mode
#[cfg(not(debug_assertions))]
fn print_backtrace(_: &Error) {}

#[cfg(debug_assertions)]
fn print_backtrace(e: &Error) {
    match e.backtrace() {
        Some(backtrace) => error!("{:?}", backtrace),
        None => error!("to view backtrace, use RUST_BACKTRACE=1"),
    }
}

fn run() -> Result<Pid> {
    let id = "rJudge";
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

    let cpath = format!{"/{}", id};

    let (tx, rx) = mpsc::channel();
    let start = SystemTime::now();

    let handle = thread::spawn(move || {
        {
            // 定时器
            let tx = tx.clone();
            thread::spawn(move || {// do something
                thread::sleep(Duration::from_millis(500));
                tx.send(Err(())).unwrap();
            });
        }
        // Do something
        do_exec("/root/loop", env::args().collect::<Vec<_>>().as_slice(), &["testt=123".to_string()]).unwrap();
        tx.send(Ok("result")).unwrap();
    });
    match rx.recv().unwrap() {
        // 计时器
        Ok(data) => println!("{:?}, {}", data, now.elapsed().unwrap().as_millis()),
        Err(err) => {
            handle.join();
            println!("timeout");
        }
    }
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
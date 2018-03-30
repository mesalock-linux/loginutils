extern crate libc;
extern crate pwhash;
#[macro_use]
extern crate lazy_static;

use std::io;
use std::io::{Read, Write, Error, ErrorKind};
use std::ffi::{CStr, CString};
use std::str;
use std::mem;
use std::ptr;
use libc::{EXIT_SUCCESS, EXIT_FAILURE};
use std::path::Path;
use std::fs::File;

static TIMEOUT: u32 = 60;

#[doc(hidden)]
pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

fn get_username() -> io::Result<String> {
    let nodename;
    unsafe {
        let mut utsname: libc::utsname = mem::uninitialized();
        cvt(libc::uname(&mut utsname))?;
        nodename = CStr::from_ptr(utsname.nodename.as_ptr()).to_string_lossy().into_owned();
    }
    if nodename.is_empty() {
        print!("?");
    } else {
        print!("{}", nodename);
    }
    print!(" login: ");
    io::stdout().flush()?;

    let mut username = String::new();
    match io::stdin().read_line(&mut username) {
        Ok(_n) => {
            Ok(String::from(username.trim()))
        }
        Err(err) => Err(err),
    }
}

fn get_password() -> io::Result<String> {
    print!("Password: ");
    io::stdout().flush()?;

    let old_termios;

    unsafe {
        let mut termios: libc::termios = mem::uninitialized();
        cvt(libc::tcgetattr(libc::STDIN_FILENO, &mut termios))?;
        old_termios = termios;    // libc::termios is a `Copy` type
        termios.c_iflag &= !(libc::IXON | libc::IXOFF | libc::IXANY);
        termios.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
        cvt(libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios))?;
    }

    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    println!();
    io::stdout().flush()?;

    unsafe {
        cvt(libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &old_termios))?;
    }

    Ok(String::from(password.trim()))
}


fn get_passwd(username: &str) -> io::Result<*mut libc::passwd> {
    let username_cstring = CString::new(username).unwrap();
    let pw = unsafe { libc::getpwnam(username_cstring.as_ptr()) };
    if pw.is_null() {
        Err(Error::new(ErrorKind::Other, "Matching entry is not found or an error occurs"))
    } else {
        Ok(pw)
    }
}

fn check_password(passwd: *mut libc::passwd, password: &str) -> io::Result<bool> {
    let pw_passwd = unsafe { CStr::from_ptr((*passwd).pw_passwd).to_string_lossy().to_owned() };

    match pw_passwd.as_ref() {
        // account is locked or no password
        "!" | "*" => {
            Ok(false)
        }
        // shadow password
        "x" => {
            let hash;

            unsafe {
                let spwd = libc::getspnam((*passwd).pw_name);
                if spwd.is_null() {
                    return Err(From::from(io::Error::last_os_error()));
                }
                hash = CStr::from_ptr((*spwd).sp_pwdp).to_string_lossy().to_owned();
            }

            Ok(pwhash::unix::verify(password, &hash))
        }
        // plain correct password
        pw_passwd if pw_passwd == password => Ok(true),
        // incorrect password
        _ => Ok(false)
    }
}

fn delay(seconds: u32) {
    let mut ret = 1;
    while ret > 0 {
        ret = unsafe { libc::sleep(seconds) };
    }
}

lazy_static! {
    // save original termios settings
    static ref INIT_TERMIOS: libc::termios = unsafe {
        let mut t: libc::termios = mem::uninitialized();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut t) < 0 ||
            libc::isatty(libc::STDIN_FILENO) == 0 {
            panic!("Must be a terminal");
        }
        t
    };
}

extern fn alarm_handler(_signum: libc::c_int, _info: *mut libc::siginfo_t, _ptr: *mut libc::c_void) {
    // restore original termios settings
    unsafe {
        let termios_ptr = Box::into_raw(Box::new(INIT_TERMIOS.clone()));
        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, termios_ptr) == -1 {
            libc::_exit(EXIT_FAILURE)
        }
        Box::from_raw(termios_ptr);
    }
    println!("\r\nLogin timed out after {} seconds\r\n", TIMEOUT);
    match io::stdout().flush() {
        Ok(_) => unsafe { libc::_exit(EXIT_SUCCESS) },
        Err(_) => unsafe { libc::_exit(EXIT_FAILURE) }
    }
}

fn main() {
    unsafe {
        if libc::signal(libc::SIGALRM, alarm_handler as usize) == libc::SIG_ERR {
            libc::exit(EXIT_FAILURE);
        }
        libc::alarm(TIMEOUT);
    }
    enum State {
        U, // get username
        P, // get password
        C, // check password with username
        F, // failed and restart
        X, // exit
    }
    let mut username = String::new();
    let mut password = String::new();
    let mut state = State::U;
    let tries = 3;
    let mut failcount = 0;
    let mut passwd: *mut libc::passwd = ptr::null_mut();
    loop {
        unsafe {
            if libc::tcflush(0, libc::TCIFLUSH) == -1 {
                libc::exit(EXIT_FAILURE);
            }
        }
        state = match state {
            State::U => match get_username() {
                Ok(ret) => {
                    username = ret;
                    if !username.is_empty() {
                        State::P
                    } else {
                        println!();
                        State::F
                    }
                }
                Err(_) => {
                    State::F
                }
            },
            State::P => match get_password() {
                Ok(ret) => {
                    password = ret;
                    match get_passwd(&username) {
                        Ok(ret) => {
                            passwd = ret;
                            State::C
                        }
                        Err(_) => {
                            State::F
                        }
                    }
                }
                Err(_) => {
                    State::F
                }
            },
            State::C => match check_password(passwd, &password) {
                Ok(true) => {
                    println!("Login success");
                    break;
                }
                Ok(false) | Err(_) => {
                    State::F
                }
            },
            State::F => {
                delay(3);
                println!("\nLogin incorrect");
                failcount += 1;
                if failcount < tries {
                    State::U
                } else {
                    eprintln!("max retries(3)");
                    State::X
                }
            }
            State::X => {
                unsafe { libc::exit(EXIT_FAILURE) };
            }
        }
    }
    unsafe {
        libc::alarm(0);

        let path = "/etc/nologin";
        if (*passwd).pw_uid != 0 && libc::access(CString::new(path).unwrap().as_ptr(), libc::R_OK) == 0 {
            let mut file = match File::open(&Path::new(path)) {
                Ok(file) => file,
                Err(_) => libc::exit(EXIT_FAILURE)
            };
            let mut message = String::new();
            match file.read_to_string(&mut message) {
                Ok(0) => println!("nologin"),
                Ok(_) => println!("{}", message),
                Err(_) => libc::exit(EXIT_FAILURE)
            }
            libc::exit(EXIT_FAILURE)
        }

        if libc::initgroups((*passwd).pw_name, (*passwd).pw_gid) == -1 ||
           libc::setgid((*passwd).pw_gid) == -1 ||
           libc::setuid((*passwd).pw_uid) == -1 {
            libc::exit(EXIT_FAILURE);
        }

        if libc::chdir((*passwd).pw_dir) == -1 {
            println!("bad $HOME: {}", CStr::from_ptr((*passwd).pw_dir).to_string_lossy());
        }

        libc::setenv(CString::new("USER").unwrap().as_ptr(), (*passwd).pw_name, 1);
        libc::setenv(CString::new("LOGNAME").unwrap().as_ptr(), (*passwd).pw_name, 1);
        libc::setenv(CString::new("HOME").unwrap().as_ptr(), (*passwd).pw_dir, 1);
        libc::setenv(CString::new("SHELL").unwrap().as_ptr(), (*passwd).pw_shell, 1);

        if libc::signal(libc::SIGINT, libc::SIG_DFL) == libc::SIG_ERR {
            libc::exit(EXIT_FAILURE);
        };

        if libc::execl((*passwd).pw_shell, (*passwd).pw_shell, ptr::null() as *const libc::c_char) == -1 {
            libc::exit(EXIT_FAILURE);
        }
    }
}

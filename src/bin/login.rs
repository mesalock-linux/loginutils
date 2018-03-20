extern crate libc;
extern crate pwhash;
#[macro_use]
extern crate lazy_static;

use std::io;
use std::io::Write;
use std::ffi::{CStr, CString};
use std::fmt;
use std::error::Error;
use std::ffi;
use std::str;
use std::mem;
use std::process;

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

fn get_username() -> Result<String, LoginError> {
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
        Err(err) => Err(LoginError::Io(err)),
    }
}

fn get_password() -> Result<String, LoginError> {
    print!("Password: ");
    io::stdout().flush()?;

    let old_termios;

    unsafe {
        let mut termios: libc::termios = mem::uninitialized();
        cvt(libc::tcgetattr(libc::STDIN_FILENO, &mut termios))?;
        old_termios = termios;    // libc::termios is a `Copy` type
        termios.c_iflag &= !(libc::IXON | libc::IXOFF | libc::IXANY);
        termios.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios);
    }

    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    println!();
    io::stdout().flush()?;

    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &old_termios);
    }

    Ok(String::from(password.trim()))
}

fn check_password(username: &str, password: &str) -> Result<bool, LoginError> {
    let username_cstring = CString::new(username)?;
    let passwd;
    unsafe {
        let pw = libc::getpwnam(username_cstring.as_ptr());
        if pw.is_null() {
            return Err(From::from(io::Error::last_os_error()));
        }
        passwd = CStr::from_ptr((*pw).pw_passwd).to_string_lossy().to_owned();
    }

    match passwd.as_ref() {
        "x" => {
            let hash;

            unsafe {
                let pw = libc::getpwnam(username_cstring.as_ptr());
                if pw.is_null() {
                    return Err(From::from(io::Error::last_os_error()));
                }
                let sp = libc::getspnam((*pw).pw_name);
                if sp.is_null() {
                    return Err(From::from(io::Error::last_os_error()));
                }
                hash = CStr::from_ptr((*sp).sp_pwdp).to_str()?;
            }

            Ok(pwhash::unix::verify(password, hash))
        },
        passwd if passwd == password => Ok(true),
        _ => Ok(false)
    }
}

#[derive(Debug)]
enum LoginError {
    Io(io::Error),
    Ffi(ffi::NulError),
    Str(str::Utf8Error)
}

impl From<io::Error> for LoginError {
    fn from(error: io::Error) -> LoginError {
        LoginError::Io(error)
    }
}


impl From<ffi::NulError> for LoginError {
    fn from(error: ffi::NulError) -> LoginError {
        LoginError::Ffi(error)
    }
}

impl From<str::Utf8Error> for LoginError {
    fn from(error: str::Utf8Error) -> LoginError {
        LoginError::Str(error)
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LoginError::Io(ref err) => err.fmt(f),
            LoginError::Ffi(ref err) => err.fmt(f),
            LoginError::Str(ref err) => err.fmt(f),
        }
    }
}

impl Error for LoginError {
    fn description(&self) -> &str {
        match *self {
            LoginError::Io(ref err) => err.description(),
            LoginError::Ffi(ref err) => err.description(),
            LoginError::Str(ref err) => err.description(),
        }
    }
}

fn delay(seconds: u32) {
    let mut ret = 1;
    while ret > 0 {
        ret = unsafe { libc::sleep(seconds) };
    }
}

lazy_static! {
    static ref INIT_TERMIOS: libc::termios = unsafe {
        let mut t: libc::termios = mem::uninitialized();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut t) < 0 ||
            libc::isatty(libc::STDIN_FILENO) == 0 {
            panic!("Must be a terminal");
        }
        t
    };
}

static TIMEOUT: u32 = 10;

extern fn alarm_handler(_signum: libc::c_int, _info: *mut libc::siginfo_t, _ptr: *mut libc::c_void) {
    unsafe {
        let termios_ptr = Box::into_raw(Box::new(INIT_TERMIOS.clone()));
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, termios_ptr);
        Box::from_raw(termios_ptr);
    }
    println!("\r\nLogin timed out after {} seconds\r\n", TIMEOUT);
    match io::stdout().flush() {
        Ok(_) => process::exit(0),
        Err(_) => process::exit(1)
    }
}

fn main() {
    unsafe {
        libc::signal(libc::SIGALRM, alarm_handler as usize);
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
    loop {
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
                Err(err) => {
                    eprintln!("[-] error: {}", err);
                    State::X
                }
            },
            State::P => match get_password() {
                Ok(ret) => {
                    password = ret;
                    State::C
                }
                Err(err) => {
                    eprintln!("[-] error: {}", err);
                    State::X
                }
            },
            State::C => match check_password(&username, &password) {
                Ok(true) => {
                    println!("Login success");
                    break;
                }
                Ok(false) => {
                    State::F
                }
                Err(err) => {
                    eprintln!("[-] error: {}", err);
                    State::X
                }
            },
            State::F => {
                delay(3);
                println!("\nLogin incorrect");
                failcount += 1;
                if failcount < tries {
                    State::U
                } else {
                    eprintln!("[-] error: exceed three tries");
                    State::X
                }
            }
            State::X => {
                eprintln!("[-] exit");
                process::exit(1);
            }
        }
    }
}

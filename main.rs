// CS444 Assignment #2 - Writing Your Own Shell
// Spring 2014 - Corey Richardson
//
// This is very unidiomatic Rust. It should rather use std::run, but in the
// spirit of the assignment, I have rolled my own using libc directly.

extern crate libc;
#[macro_use] extern crate log;

use std::os;
use std::ffi::CString;
use std::old_io::BufferedReader;
use libc::{c_char, c_int};
use std::old_io::{stdin, stdout, stderr};
use std::old_io::fs::PathExtensions;
use std::old_path::BytesContainer;
use libc::funcs::posix88::signal::kill;
use libc::funcs::posix88::unistd::fork;
use std::mem::transmute;

// from bits/waitflags.h; glibc specific. no bindings in std::libc
static WNOHANG: c_int = 1;
static WCONTINUED: c_int = 8;

extern {
    fn waitpid(child: c_int, stat_loc: *mut c_int, options: c_int) -> c_int ;
}

struct Shell {
    jobs: Vec<(isize, libc::pid_t)>,
    job_id: isize,
    history: Vec<Command>
}

#[derive(Clone)]
struct Command {
    /// Program to run (first non-env-var-setting part of line)
    program: String,
    arguments: Vec<CString>,
    env_vars: Vec<(String, String)>,
    out: Option<String>,
    in_: Option<String>,
    bg: bool,
}

fn from_str<T: std::str::FromStr>(x: &str) -> Option<T> {
    std::str::FromStr::from_str(x).ok()
}

impl std::fmt::String for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, " {}", self.program);
        for arg in self.arguments.iter() {
            write!(f, " {}", arg.container_as_str().unwrap());
        }
        self.out.as_ref().map(|o| write!(f, " > {}", *o));
        self.in_.as_ref().map(|i| write!(f, " < {}", *i));
        if self.bg {
            write!(f, "&");
        }
        Ok(())
    }
}

fn dupfd(p: &str, to_fd: c_int, flags: c_int) {
    let ps = CString::from_slice(p.as_bytes());
    let fd = unsafe { libc::open(ps.as_bytes_with_nul().as_ptr() as *const _, flags, libc::S_IRWXU) };
    if unsafe { libc::dup2(fd, to_fd) } != to_fd {
        panic!("fcntl returned -1, errno={}", os::last_os_error());
    }
}

impl Shell {
    fn new() -> Shell {
        Shell { jobs: Vec::new(), history: Vec::new(), job_id: 0 }
    }

    fn maybe_builtin(&self, cmd: &Command) -> Option<isize> {
        match cmd.program.as_slice() {
            "jobs" => {
                for &(jid, pid) in self.jobs.iter() {
                    println!("job {} is running, pid {}", jid, pid);
                }
                Some(0)
            },
            "cd" => {
                match cmd.arguments.get(0) {
                    Some(p) => { os::change_dir(&Path::new(p.container_as_str().unwrap())); },
                    None    => { writeln!(&mut stderr(), "cd requires an argument"); return Some(1); }
                }
                Some(0)
            },
            "history" => {
                let n = cmd.arguments.get(0).map_or(self.history.len(), |x| from_str(x.container_as_str().unwrap()).unwrap());
                for (num, cmd) in self.history.iter().enumerate().take(n) {
                    println!("{}: {}", num+1, *cmd);
                }
                Some(0)
            },
            "exit" => {
                if self.jobs.len() != 0 {
                    println!("Not exiting; there are jobs running");
                } else {
                    unsafe {
                        libc::exit(cmd.arguments.get(0)
                                      .map_or(0, |s| from_str(s.container_as_str().unwrap()).unwrap()));
                    }
                }
                Some(1)
            },
            "kill" => {
                match cmd.arguments.get(0) {
                    Some(p) => {
                        let p = p.container_as_str().unwrap();
                        if p.starts_with("%") {
                            let jid = from_str(p.slice_from(1)).unwrap();
                            let pid = self.jobs.iter().find(|& &(_, j)| j == jid);
                            pid.map(|&(_, pid)| unsafe { kill(pid, libc::SIGKILL) });
                        } else {
                            let pid: Option<libc::pid_t> = from_str(p);
                            pid.map(|pid| unsafe { kill(pid as libc::pid_t, libc::SIGKILL) });
                        }
                        Some(0)
                    },
                    None => { writeln!(&mut stderr(), "kill needs an argument (pid)"); Some(0) }
                }
            },
            "help" => {
                match cmd.arguments.get(0) {
                    Some(c) => match c.container_as_str().unwrap() {
                        "jobs" => println!("jobs - print list of running background jobs"),
                        "cd" => println!("cd <dir> - change cwd to <dir>"),
                        "history" => println!("history [n] - print the last n lines of history (default, all history)"),
                        "kill" => println!("kill [pid | %jid] - kill the given pid or job with id jid"),
                        "help" => println!("help <builtin> - print help for <builtin>"),
                        b      => println!("unknown builtin {}", b)
                    },
                    None => println!("builtins: jobs, cd, history, kill, help")
                }
                Some(0)
            },
            _ => None
        }
    }

    /// Run the command in a new process.
    fn execute(&mut self, cmd: Command) -> Option<isize> {
        // execute from history
        if cmd.program.starts_with("!") {
            match from_str::<isize>(cmd.program.slice_from(1)) {
                Some(mut v) => {
                    let mut v = v as usize;
                    if v < 0 {
                        v = self.history.len() + v;
                    }
                    if v > self.history.len() || v < 0 {
                        writeln!(&mut stderr(), "tried to run non-existent history item {}", v);
                        return Some(1);
                    }
                    let cmd2 = self.history[v].clone();
                    self.execute(cmd2);
                    return Some(0);
                },
                None => {
                    writeln!(&mut stderr(), "invalid index in !num execution");
                    return Some(1);
                }
            }
        }

        match self.maybe_builtin(&cmd) {
            Some(s) => return Some(s),
            None => ()
        }
        if "" == cmd.program { return None }
        let cmd_ = match find_cmd(&cmd.program) {
            Some(c) => c,
            None => {
                writeln!(&mut stderr(), "command not found: {}", cmd.program);
                return None;
            }
        };

        // this is very disgusting.
        match unsafe { fork() } {
            0 => {
                // we are child
                let cstr = CString::from_slice(cmd_.as_vec());
                let cstr = cstr.as_bytes_with_nul().as_ptr();
                // setup argv
                let mut args = vec![cstr];
                args.extend(&mut cmd.arguments.iter().map(|x| x.as_bytes_with_nul().as_ptr()));
                args.push(0 as *const u8);

                // setup envp
                let mut env = os::env();
                env.extend(&mut cmd.env_vars.iter().map(|p| p.clone()));
                let env: Vec<CString> = env.iter()
                                        .map(|&(ref a, ref b)| CString::from_slice(format!("{}={}", *a, *b).as_bytes()))
                                        .collect();

                let mut env2: Vec<*mut c_char> = env.iter().map(|x| x.as_bytes().as_ptr() as *mut _).collect();
                env2.push(0 as *mut c_char);

                // redirection?
                cmd.out.as_ref().map(|o| dupfd(o, libc::STDOUT_FILENO, libc::O_CREAT | libc::O_RDWR));
                cmd.in_.as_ref().map(|i| dupfd(i, libc::STDIN_FILENO, libc::O_RDONLY));

                if unsafe { libc::execve(transmute(cstr), transmute(args.as_ptr()), transmute(env2.as_ptr())) } == -1 {
                    panic!("execve failed, errno={}", os::last_os_error());
                }
                unreachable!()
            },
            child_pid if child_pid > 0 => {
                let bg = cmd.bg;
                self.history.push(cmd);
                if bg {
                    self.jobs.push((self.job_id+1, child_pid));
                    self.job_id += 1;
                    return None;
                }
                let mut res = 0;
                let res = unsafe { waitpid(child_pid, &mut res, 0) };
                if WIFEXITED(res) {
                    let res = WEXITSTATUS(res);
                    debug!("child exited with {}", res);
                    return Some(res as isize);
                } else {
                    info!("child exited abnormally (signal?");
                    panic!("unimplemented")
                }
            },
            error if error < 0 => panic!("fork error {}", error),
            _ => unreachable!()
        }
    }
}

fn prompt() -> String {
    let cwd = os::getcwd();
    format!("{}> ", cwd.unwrap().display())
}

fn parse_line(l: &str) -> Command {
    // yikes, ad-hoc parser!
    let mut env_vars = Vec::new();
    let mut args = Vec::new();
    let mut program = "".to_string();
    let mut out_file = None;
    let mut in_file = None;
    let mut found_bg = false;

    let mut seen_non_eq = false;

    let mut words = l.words();
    loop {
        match words.next() {
            Some(word) => {
                // env var, program, or arg
                if !seen_non_eq {
                    // env var or program
                    if !word.contains_char('=') {
                        // program
                        seen_non_eq = true;
                        program = word.to_string();
                    } else {
                        // env var
                        let idx = word.find('=').unwrap();
                        let env_entry = (word.slice_to(idx).to_string(), word.slice_from(idx+1).to_string());
                        env_vars.push(env_entry);
                    }
                } else {
                    match word {
                        ">" => out_file = Some(words.next().expect("no out file in redirection").to_string()),
                        "<" => in_file = Some(words.next().expect("no in file in redirectoin").to_string()),
                        "&" => found_bg = true,
                        _   => { found_bg = false; args.push(CString::from_slice(word.as_bytes())) }
                    }
                }
            },
            None => {
                break
            }
        }
    }
    Command {
        program: program,
        arguments: args,
        env_vars: env_vars,
        out: out_file,
        in_: in_file,
        bg: found_bg,
    }
}

fn find_cmd(cmd: &str) -> Option<Path> {
    let p = Path::new(cmd);
    if p.exists() {
        return Some(p);
    }
    let path = os::getenv("PATH").unwrap_or_else(|| ".:/usr/bin:/bin".to_string());
    for entry in path.split(':') {
        let mut p = Path::new(entry);
        p.push(cmd);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn main() {
    let mut shell = Shell::new();
    let mut stdin = BufferedReader::new(stdin());
    let mut stdout = stdout();
    loop {
        // shell mainloop
        let p = prompt();
        stdout.write(p.as_bytes());
        stdout.flush();

        match stdin.read_line() {
            Ok(s) => {
                // do we have any waiting jobs?
                let mut remove_jobs = Vec::new();
                for &(jid, pid) in shell.jobs.iter() {
                    let mut res = 0;
                    let res = unsafe { waitpid(pid, &mut res, WNOHANG | WCONTINUED) };
                    if WIFEXITED(res) {
                        remove_jobs.push(jid);
                        println!("job {} has exited", jid);
                    }
                }
                let mut jobs = shell.jobs.iter().map(|x| x.clone())
                                     .filter(|&(jid, _)| !remove_jobs.contains(&jid)).collect();
                std::mem::swap(&mut jobs, &mut shell.jobs);
                let cmd = parse_line(s.trim());
                shell.execute(cmd);
            },
            Err(e) => unsafe { println!("{}", e); libc::exit(0) }
        }
    }
}

// C interop
//
fn WEXITSTATUS(status: c_int) -> c_int {
     (((status) & 0xff00) >> 8)
}

fn WIFEXITED(status: c_int) -> bool {
    WTERMSIG(status) != 0
}

fn WTERMSIG(status: c_int) -> c_int {
    ((status) & 0x7f)
}

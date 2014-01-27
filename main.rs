// CS444 Assignment #2 - Writing Your Own Shell
// Spring 2014 - Corey Richardson
//
// This is very unidiomatic Rust. It should rather use std::run, but in the
// spirit of the assignment, I have rolled my own using libc directly.

// don't use the libuv-based M:N threaded runtime
#[no_uv];
#[crate_id = "cmrsh"];

// link to the native runtime
extern mod native;

use std::os;
use std::libc;
use std::c_str::CString;
use std::io::BufferedReader;
use std::libc::{c_char, c_int};
use std::io::{stdin, stdout, stderr};
use std::libc::funcs::posix88::signal::kill;
use std::libc::funcs::posix01::wait::waitpid;

// from bits/waitflags.h; glibc specific. no bindings in std::libc
static WNOHANG: c_int = 1;
static WCONTINUED: c_int = 8;

struct Shell {
    jobs: ~[(int, libc::pid_t)],
    job_id: int,
    history: ~[Command]
}

struct Command {
    /// Program to run (first non-env-var-setting part of line)
    program: ~str,
    arguments: ~[CString],
    env_vars: ~[(~str, ~str)],
    out: Option<~str>,
    in_: Option<~str>,
    bg: bool,
}

impl std::fmt::Default for Command {
    fn fmt(v: &Command, f: &mut std::fmt::Formatter) {
        write!(f.buf, " {}", v.program);
        for arg in v.arguments.iter() {
            write!(f.buf, " {}", arg.as_str());
        }
        v.out.as_ref().map(|o| write!(f.buf, " > {}", *o));
        v.in_.as_ref().map(|i| write!(f.buf, " < {}", *i));
        if v.bg {
            write!(f.buf, "&");
        }
    }
}

fn dupfd(p: &str, to_fd: c_int, flags: c_int) {
    let fd = p.with_c_str(|cstr| {
        unsafe { libc::open(cstr, flags, libc::S_IRWXU) }
    });
    if unsafe { libc::dup2(fd, to_fd) } != to_fd {
        fail!("fcntl returned -1, errno={}", os::last_os_error());
    }
}

impl Shell {
    fn new() -> Shell {
        Shell { jobs: ~[], history: ~[], job_id: 0 }
    }

    fn maybe_builtin(&self, cmd: &Command) -> Option<int> {
        return match cmd.program.as_slice() {
            "jobs" => {
                for &(jid, pid) in self.jobs.iter() {
                    println!("job {} is running, pid {}", jid, pid);
                }
                Some(0)
            },
            "cd" => {
                match cmd.arguments.get(0) {
                    Some(p) => { os::change_dir(&Path::new(p.as_str().unwrap())); },
                    None    => { writeln!(&mut stderr(), "cd requires an argument"); return Some(1); }
                }
                Some(0)
            },
            "history" => {
                let n = cmd.arguments.get(0).map_or(self.history.len(), |x| from_str(x.as_str().unwrap()).unwrap());
                for (num, cmd) in self.history.rev_iter().take(n).enumerate() {
                    println!("{}: {}", num, *cmd);
                }
                Some(0)
            },
            "exit" => {
                if self.jobs.len() != 0 {
                    println!("Not exiting; there are jobs running");
                } else {
                    unsafe {
                        std::libc::exit(cmd.arguments.get(0)
                                        .map_or(0, |s| from_str(s.as_str().unwrap()).unwrap()));
                    }
                }
                Some(1)
            },
            "kill" => {
                match cmd.arguments.get(0) {
                    Some(p) => {
                        let p = p.as_str().unwrap();
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
                    Some(c) => match c.as_str().unwrap() {
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
    fn execute(&mut self, cmd: Command) -> Option<int> {
        match self.maybe_builtin(&cmd) {
            Some(s) => return Some(s),
            None => ()
        }
        if "" == cmd.program { return None }
        let cmd_ = match find_cmd(cmd.program) {
            Some(c) => c,
            None => {
                writeln!(&mut stderr(), "command not found: {}", cmd.program);
                return None;
            }
        };

        // this is very disgusting.
        match unsafe { libc::fork() } {
            0 => {
                // we are child
                cmd_.with_c_str(|cstr| {
                    // setup argv
                    let mut args = ~[cstr];
                    args.extend(&mut cmd.arguments.iter().map(|x| x.with_ref(|y| y)));
                    args.push(0 as *c_char);

                    // setup envp
                    let mut env = os::env();
                    env.extend(&mut cmd.env_vars.iter().map(|p| p.clone()));
                    let env: ~[CString] = env.iter()
                                          .map(|&(ref a, ref b)| format!("{}={}", *a, *b).to_c_str())
                                          .collect();

                    let mut env2: ~[*c_char] = env.iter().map(|x| x.with_ref(|y| y)).collect();
                    env2.push(0 as *c_char);

                    // redirection?
                    cmd.out.as_ref().map(|o| dupfd(*o, libc::STDOUT_FILENO, libc::O_CREAT | libc::O_RDWR));
                    cmd.in_.as_ref().map(|i| dupfd(*i, libc::STDIN_FILENO, libc::O_RDONLY));

                    if unsafe { libc::execve(cstr, args.as_ptr(), env2.as_ptr()) } == -1 {
                        fail!("execve failed, errno={}", os::last_os_error());
                    }
                });
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
                    return Some(res as int);
                } else {
                    info!("child exited abnormally (signal?");
                    fail!("unimplemented")
                }
            },
            error if error < 0 => fail!("fork error {}", error),
            _ => unreachable!()
        }
    }
}

fn prompt() -> ~str {
    let cwd = os::getcwd();
    format!("{}> ", cwd.display())
}

fn parse_line(l: &str) -> Command {
    // yikes, ad-hoc parser!
    let mut env_vars = ~[];
    let mut args = ~[];
    let mut program = ~"";
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
                        program = word.to_owned();
                    } else {
                        // env var
                        let idx = word.find('=').unwrap();
                        let env_entry = (word.slice_to(idx).to_owned(), word.slice_from(idx+1).to_owned());
                        env_vars.push(env_entry);
                    }
                } else {
                    match word {
                        ">" => out_file = Some(words.next().expect("no out file in redirection").to_owned()),
                        "<" => in_file = Some(words.next().expect("no in file in redirectoin").to_owned()),
                        "&" => found_bg = true,
                        _   => { found_bg = false; args.push(word.to_c_str()) }
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
    let path = os::getenv("PATH").unwrap_or_else(|| ~".:/usr/bin:/bin");
    for entry in path.split(':') {
        let mut p = Path::new(entry);
        p.push(cmd);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

// entry point
#[start]
fn main(argc: int, argv: **u8) -> int {
    // start the runtime
    do native::start(argc, argv) {
        let mut shell = Shell::new();
        let mut stdin = BufferedReader::new(stdin());
        let mut stdout = stdout();
        loop {
            // shell mainloop
            let p = prompt();
            stdout.write(p.as_bytes());

            match stdin.read_line() {
                Some(s) => {
                    // do we have any waiting jobs?
                    let mut remove_jobs = ~[];
                    for &(jid, pid) in shell.jobs.iter() {
                        let mut res = 0;
                        let res = unsafe { waitpid(pid, &mut res, WNOHANG | WCONTINUED) };
                        if WIFEXITED(res) {
                            remove_jobs.push(jid);
                            println!("job {} has exited", jid);
                        } else if res != 0xFFFF {
                            // W_CONTINUED
                            continue;
                        }
                    }
                    let mut jobs = shell.jobs.iter().map(|x| x.clone())
                                         .filter(|&(jid, _)| !remove_jobs.contains(&jid)).collect();
                    std::util::swap(&mut jobs, &mut shell.jobs);
                    let cmd = parse_line(s.trim());
                    shell.execute(cmd);
                },
                None => unsafe { println!(""); std::libc::exit(0) }
            }
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

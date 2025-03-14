use anyhow::{Context, Result, anyhow};
use nix::mount::umount;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, fork};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::prelude::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

#[derive(Serialize, Deserialize, Debug)]
enum Node {
	File {
		path: PathBuf,
		content: Vec<u8>,
	},
	Directory {
		path: PathBuf,
		children: HashMap<String, Node>,
	},
}

struct Environment {
	temp_dir: TempDir,
	mount_points: Vec<PathBuf>,
}

impl Environment {
	fn new() -> Result<Self> {
		let temp_dir = TempDir::new()?;

		Ok(Environment {
			temp_dir,
			mount_points: Vec::new(),
		})
	}

	fn mount_tmpfs(&mut self, target: &Path) -> Result<()> {
		fs::create_dir_all(target)?;

		mount(
			Some("none"),
			target,
			Some("tmpfs"),
			MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
			Some("mode=755"),
		)?;

		self.mount_points.push(target.to_path_buf());
		Ok(())
	}

	/// Recreate the hardware information tree from the binary dump
	fn populate_from_dump(&mut self, dump_path: &Path) -> Result<()> {
		let mut file = File::open(dump_path).context("Failed to open hardware information dump file")?;
		let mut data = Vec::new();
		file.read_to_end(&mut data)?;

		let (tree, command_results): (HashMap<String, Node>, HashMap<String, Vec<u8>>) =
			bincode::deserialize(&data).context("Failed to deserialize hardware information")?;

		let sys_path = self.temp_dir.path().join("sys");
		let proc_path = self.temp_dir.path().join("proc");
		let dev_path = self.temp_dir.path().join("dev");

		self.mount_tmpfs(&sys_path)?;
		self.mount_tmpfs(&proc_path)?;
		self.mount_tmpfs(&dev_path)?;

		for (name, node) in tree {
			let base_path = if name.starts_with("sys") {
				&sys_path
			} else if name.starts_with("proc") {
				&proc_path
			} else if name.starts_with("dev") {
				&dev_path
			} else {
				continue;
			};

			self.create_node(base_path, &node)?;
		}

		let cmd_results_path = self.temp_dir.path().join("command_results.bin");
		let cmd_data = bincode::serialize(&command_results)?;
		fs::write(&cmd_results_path, cmd_data)?;

		Ok(())
	}

	fn create_node(&self, base_path: &Path, node: &Node) -> Result<()> {
		match node {
			Node::File { path, content } => {
				let full_path = base_path.join(path);

				if let Some(parent) = full_path.parent() {
					fs::create_dir_all(parent)?;
				}

				fs::write(&full_path, content)?;

				let mut perms = fs::metadata(&full_path)?.permissions();
				perms.set_mode(0o444);
				fs::set_permissions(&full_path, perms)?;
			},
			Node::Directory { path, children } => {
				let full_path = base_path.join(path);

				fs::create_dir_all(&full_path)?;

				for (_name, child) in children {
					self.create_node(base_path, child)?;
				}
			},
		}

		Ok(())
	}

	fn generate_ld_preload(&self) -> Result<PathBuf> {
		let lib_path = self.temp_dir.path().join("steamdeck_spoof.so");
		let source_path = self.temp_dir.path().join("steamdeck_spoof.c");

		let source = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/input.h>

// Path to our fake filesystem root
static const char *FAKE_ROOT = NULL;

__attribute__((constructor))
static void init(void) {
    FAKE_ROOT = getenv("STEAMDECK_SPOOF_ROOT");
}

// Intercept open() to redirect reads from system directories
int open(const char *path, int flags, ...) {
    static int (*real_open)(const char*, int, ...) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    if (FAKE_ROOT && (
        strncmp(path, "/sys/", 5) == 0 ||
        strncmp(path, "/proc/", 6) == 0 ||
        strncmp(path, "/dev/input/", 11) == 0)) {
        
        // Calculate path in our fake filesystem
        char new_path[PATH_MAX];
        snprintf(new_path, sizeof(new_path), "%s%s", FAKE_ROOT, path);
        
        // Try to open our fake path first
        int fd = real_open(new_path, flags, mode);
        if (fd >= 0) {
            return fd;
        }
    }
    
    // Fallback to real open
    return real_open(path, flags, mode);
}

// Intercept stat/fstat/lstat
int __xstat(int ver, const char *path, struct stat *buf) {
    static int (*real_xstat)(int, const char*, struct stat*) = NULL;
    if (!real_xstat) {
        real_xstat = dlsym(RTLD_NEXT, "__xstat");
    }
    
    if (FAKE_ROOT && (
        strncmp(path, "/sys/", 5) == 0 ||
        strncmp(path, "/proc/", 6) == 0 ||
        strncmp(path, "/dev/input/", 11) == 0)) {
        
        char new_path[PATH_MAX];
        snprintf(new_path, sizeof(new_path), "%s%s", FAKE_ROOT, path);
        
        // Try stat on our fake path first
        int result = real_xstat(ver, new_path, buf);
        if (result == 0) {
            return result;
        }
    }
    
    return real_xstat(ver, path, buf);
}

// Intercept uname to provide Steam Deck information
int uname(struct utsname *buf) {
    static int (*real_uname)(struct utsname*) = NULL;
    if (!real_uname) {
        real_uname = dlsym(RTLD_NEXT, "uname");
    }
    
    int result = real_uname(buf);
    if (result == 0) {
        // Modify to match Steam Deck
        strncpy(buf->nodename, "steamdeck", sizeof(buf->nodename) - 1);
        strncpy(buf->version, "SteamOS", sizeof(buf->version) - 1);
    }
    
    return result;
}

// Intercept ioctl for input device queries
int ioctl(int fd, unsigned long request, ...) {
    static int (*real_ioctl)(int, unsigned long, ...) = NULL;
    if (!real_ioctl) {
        real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    }
    
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void*);
    va_end(args);
    
    // Handle input device identification
    if (request == EVIOCGNAME(256) && arg) {
        // Check if this might be querying an input device
        char fdpath[PATH_MAX];
        char filepath[PATH_MAX];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        
        if (readlink(fdpath, filepath, sizeof(filepath)) != -1) {
            if (strstr(filepath, "/dev/input/")) {
                // This is an input device query, return Steam Deck controller name
                char *name = (char*)arg;
                strncpy(name, "Valve Steam Deck Controller", 256);
                return 0;
            }
        }
    }
    
    return real_ioctl(fd, request, arg);
}
"#;

		fs::write(&source_path, source)?;

		let status = Command::new("gcc")
			.args(&[
				"-fPIC",
				"-shared",
				"-o",
				lib_path.to_str().unwrap(),
				source_path.to_str().unwrap(),
				"-ldl",
			])
			.status()
			.context("Failed to compile LD_PRELOAD library")?;

		if !status.success() {
			return Err(anyhow!("Failed to compile LD_PRELOAD library"));
		}

		Ok(lib_path)
	}

	fn run_command(&self, command: &str, args: &[String]) -> Result<()> {
		unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS).context("Failed to create namespace")?;

		let lib_path = self.generate_ld_preload()?;

		match unsafe { fork()? } {
			ForkResult::Parent { child } => {
				waitpid(child, None)?;
			},
			ForkResult::Child => {
				unsafe {
					env::set_var("LD_PRELOAD", lib_path);
					env::set_var("STEAMDECK_SPOOF_ROOT", self.temp_dir.path());
					env::set_var("SteamDeck", "1");
					env::set_var("STEAM_DECK", "1");
					env::set_var("SDL_GAMECONTROLLER_ALLOW_STEAM_VIRTUAL_GAMEPAD", "1");
				}
				let err = Command::new(command).args(args).exec();

				eprintln!("Failed to execute command: {:?}", err);
				std::process::exit(1);
			},
		}

		Ok(())
	}
}

impl Drop for Environment {
	fn drop(&mut self) {
		for mount_point in self.mount_points.iter().rev() {
			let _ = umount(mount_point.as_path());
		}
	}
}

fn main() -> Result<()> {
	let args: Vec<String> = env::args().collect();

	if args.len() < 3 {
		eprintln!("Usage: steamdeckrun <path_to_hardware_dump> <command> [args...]");
		return Ok(());
	}

	let dump_path = Path::new(&args[1]);
	let command = &args[2];
	let command_args = &args[3..];

	if !dump_path.exists() {
		return Err(anyhow!("Hardware dump file not found: {}", dump_path.display()));
	}

	let mut env = Environment::new()?;
	env.populate_from_dump(dump_path)?;

	env.run_command(command, &command_args.iter().map(|s| s.to_string()).collect::<Vec<_>>())?;

	Ok(())
}

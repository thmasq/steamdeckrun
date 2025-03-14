use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

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

impl Node {
	fn from_path(base_path: &Path, path: &Path) -> Result<Self> {
		if path.is_dir() {
			let mut children = HashMap::new();

			for entry in fs::read_dir(path).context(format!("Failed to read directory: {}", path.display()))? {
				let entry = entry?;
				let entry_path = entry.path();
				let _rel_path = entry_path.strip_prefix(base_path).unwrap_or(&entry_path);

				if Self::should_skip(&entry_path) {
					continue;
				}

				if let Ok(node) = Self::from_path(base_path, &entry_path) {
					let name = entry_path.file_name().unwrap_or_default().to_string_lossy().to_string();
					children.insert(name, node);
				}
			}

			Ok(Node::Directory {
				path: path.strip_prefix(base_path)?.to_path_buf(),
				children,
			})
		} else {
			let content = fs::read(path).unwrap_or_default();

			Ok(Node::File {
				path: path.strip_prefix(base_path)?.to_path_buf(),
				content,
			})
		}
	}

	fn should_skip(path: &Path) -> bool {
		let path_str = path.to_string_lossy();

		path_str.contains("/proc/kcore")
			|| path_str.contains("/proc/kallsyms")
			|| path_str.contains("/proc/self")
			|| path_str.contains("/proc/sched")
			|| path_str.contains("/proc/timer")
			|| path_str.contains("/sys/kernel/debug")
			|| path_str.contains("/sys/fs/cgroup")
			|| path_str.contains("/sys/firmware")
			|| path_str.contains("/dev/shm")
			|| path_str.contains("/dev/pts")
			|| path_str.contains("/proc/[0-9]")
	}
}

fn main() -> Result<()> {
	// Paths that contain Steam Deck hardware information
	let paths_to_dump = vec![
		"/sys/devices/virtual/dmi/id", // Basic system info
		"/sys/class/input",            // Input devices
		"/sys/class/drm",              // Display info
		"/sys/class/hwmon",            // Hardware monitoring (temps, fans)
		"/sys/devices/platform",       // Platform devices
		"/sys/devices/pci0000:00",     // PCI devices
		"/sys/bus/usb/devices",        // USB devices
		"/dev/input",                  // Input device nodes
		"/proc/cpuinfo",               // CPU info
		"/proc/meminfo",               // Memory info
	];

	// Also collect output from commands
	let commands_to_run = vec![
		("uname", vec!["-a"]),
		("lsusb", vec![]),
		("lspci", vec![]),
		("lsblk", vec!["-J"]),
		("cat", vec!["/etc/os-release"]),
		("journalctl", vec!["-b", "-g", "Valve"]), // Any Valve-specific boot logs
	];

	let mut root = HashMap::new();

	for path_str in paths_to_dump {
		let path = Path::new(path_str);
		if path.exists() {
			let base_path = match path.parent() {
				Some(parent) => parent,
				None => Path::new("/"),
			};

			if let Ok(node) = Node::from_path(base_path, path) {
				let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

				root.insert(name, node);
			}
		}
	}

	let mut command_results = HashMap::new();
	for (cmd, args) in commands_to_run {
		if let Ok(output) = Command::new(cmd).args(&args).output() {
			let command_str = format!("{} {}", cmd, args.join(" "));
			command_results.insert(command_str, output.stdout);
		}
	}

	let output = bincode::serialize(&(root, command_results))?;
	let mut file = File::create("steamdeck_hardware_info.bin")?;
	file.write_all(&output)?;

	println!("Successfully dumped Steam Deck hardware information to steamdeck_hardware_info.bin");
	Ok(())
}

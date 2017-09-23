extern crate sysinfo;

use std::thread::sleep;
use std::time;
use sysinfo::{System, SystemExt, Process, ProcessExt, Signal};
use std::process::Command;
use std::collections::BTreeSet;
use std::fs::{OpenOptions, File};
use std::io::{Seek, SeekFrom, Read, Write};
use std::iter::FromIterator;
use std::path::Path;
use std::fs;

const POLL_SECONDS: u64 = 2;
const CPU_USAGE_THRESHOLD: f32 = 85.0;
const HOGS_THRESHOLD: u8 = 3;
const MAX_PIDS: usize = 100_000;

const CACHE_DIR: &str = "/usr/local/var/cache/hog_detector";
const NOTIFICATION_TIMEOUT: u64 = 10;
const NOTIFICATION_ICON: &str = "/Applications/Siri.app/Contents/Resources/Siri.icns";
const KILL: &str = "Kill";
const IGNORE: &str = "Ignore";

struct HogDetector {
    cache: File,
    ignored: BTreeSet<String>,
    hogs: [u8; MAX_PIDS],
}

impl HogDetector {
    pub fn new() -> HogDetector {

        HogDetector {
            ignored: HogDetector::read_ignored_from_cache(),
            cache: HogDetector::open_cache(),
            hogs: [0; MAX_PIDS],
        }
    }

    fn open_cache() -> File {
        let cache_dir_path = Path::new(CACHE_DIR);
        if !cache_dir_path.exists() {
            fs::create_dir_all(cache_dir_path).expect(&format!(
                "Can't create cache dir: {:?}",
                cache_dir_path
            ));
        }

        let cache_path = cache_dir_path.join("cache");
        OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&cache_path)
            .expect(&format!("Can't open cache file: {:?}", cache_path))
    }

    fn read_ignored_from_cache() -> BTreeSet<String> {
        let mut contents = String::new();
        let mut cache = HogDetector::open_cache();
        cache.seek(SeekFrom::Start(0)).expect(
            "Can't seek to beginning of file",
        );
        cache.read_to_string(&mut contents).expect(
            "Can't read file to string",
        );
        BTreeSet::from_iter(contents.split_terminator('\n').map(String::from))
    }

    fn ignore(&mut self, process: &Process) -> bool {
        let cmd = process.cmd.join(" ");
        self.cache.write_all(cmd.as_bytes()).expect(&format!(
            "Writing cmd failed: {}",
            cmd
        ));
        self.cache.write_all(&[b'\n']).expect(
            "Writing newline failed",
        );
        self.cache.sync_all().unwrap();
        self.ignored.insert(cmd);

        true
    }

    fn notify(&mut self, process: &Process) {
        let title = format!("{} is a hog", process.name);
        let message = format!(
            "This process is using {:.2}% of your CPU",
            process.cpu_usage
        );
        let output = Command::new("/usr/local/bin/terminal-notifier")
            .args(&["-title", &title])
            .args(&["-message", &message])
            .args(&["-actions", KILL])
            .args(&["-closeLabel", IGNORE])
            .args(&["-appIcon", NOTIFICATION_ICON])
            .args(&["-timeout", &NOTIFICATION_TIMEOUT.to_string()])
            .output()
            .expect("Failed to post notification");

        if let Ok(out) = String::from_utf8(output.stderr) {
            if let Some(action) = out.rsplitn(2, '@').next() {
                match action.trim() {
                    KILL => process.kill(Signal::Kill),
                    IGNORE => self.ignore(process),
                    _ => false,
                };
            };
        }
    }

    fn watch(&mut self) {
        let poll_seconds = time::Duration::from_secs(POLL_SECONDS);
        let mut sys = System::new();

        loop {
            sys.refresh_processes();
            let processes = sys.get_process_list();
            for (pid, process) in processes.iter() {
                let pid = *pid as usize;
                let cmd = process.cmd.join(" ");
                if self.ignored.contains(&cmd) {
                    continue;
                }
                if process.cpu_usage > CPU_USAGE_THRESHOLD {
                    if self.hogs[pid] >= HOGS_THRESHOLD {
                        self.notify(process);
                    }
                    self.hogs[pid] += 1;
                } else {
                    self.hogs[pid] = 0;
                }

            }
            sleep(poll_seconds);
        }
    }
}

fn main() {
    let mut detector = HogDetector::new();
    detector.watch();
}
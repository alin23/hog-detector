extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate rmp_serde as rmps;
extern crate sysinfo;

use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sysinfo::{Process, ProcessExt, Signal, System, SystemExt};

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time;

const POLL_SECONDS: u64 = 4;
const CPU_USAGE_THRESHOLD: f32 = 85.0;
const HOGS_THRESHOLD: u8 = 2;
const TIMEOUTS_THRESHOLD: u8 = 2;
const MAX_PIDS: usize = 100_000;

const CACHE_DIR: &str = "/usr/local/var/cache/";
const NOTIFIER_ID: &str = "hog_detector";
const NOTIFICATION_TIMEOUT: u64 = 10;
const NOTIFICATION_ICON: &str = "/Applications/Siri.app/Contents/Resources/Siri.icns";
const KILL: &str = "Kill";
const IGNORE: &str = "Ignore";
const TIMEOUT: &str = "timeout";
const CLOSED: &str = "closed";
const ACTION_CLICKED: &str = "actionClicked";

#[derive(Debug, Serialize, Deserialize)]
struct Notification {
    activationType: String,
    activationValue: Option<String>,
    activationAt: String,
    deliveredAt: String,
}

struct HogDetector {
    cache: File,
    ignored: HashMap<String, BTreeSet<String>>,
    hogs: [u8; MAX_PIDS],
    timeouts: [u8; MAX_PIDS],
}

impl HogDetector {
    pub fn new() -> Self {
        HogDetector {
            ignored: HogDetector::read_ignored_from_cache(),
            cache: HogDetector::open_cache(),
            hogs: [0; MAX_PIDS],
            timeouts: [0; MAX_PIDS],
        }
    }

    fn open_cache() -> File {
        let cache_dir_path = Path::new(CACHE_DIR);
        if !cache_dir_path.exists() {
            fs::create_dir_all(cache_dir_path).expect(&format!("Can't create cache dir: {:?}", cache_dir_path));
        }

        let cache_path = cache_dir_path.join("hog_detector");
        OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&cache_path)
            .expect(&format!("Can't open cache file: {:?}", cache_path))
    }

    fn read_ignored_from_cache() -> HashMap<String, BTreeSet<String>> {
        let mut contents = Vec::new();
        let mut cache = HogDetector::open_cache();
        cache.seek(SeekFrom::Start(0)).expect(
            "Can't seek to beginning of file",
        );
        let size = cache.read_to_end(&mut contents).expect(
            "Can't read file to end",
        );

        if size == 0 {
            return HashMap::new();
        }

        let mut de = Deserializer::new(&contents[..]);
        Deserialize::deserialize(&mut de).expect("Can't deserialize cache")
    }

    fn ignore(&mut self, process: &Process) -> bool {
        let cmd = process.cmd.join(" ");
        let cmds = self.ignored.entry(process.exe.to_string()).or_insert_with(
            BTreeSet::new,
        );
        cmds.insert(cmd)
    }

    fn dump_cache(&mut self) {
        self.cache.set_len(0).expect("Couldn't truncate cache");
        self.ignored
            .serialize(&mut Serializer::new(&mut self.cache))
            .expect("Couldn't dump cache");
    }

    fn notify(&mut self, process: &Process) {
        let title = format!("{} is a hog", process.name);
        let message = format!(
            "This process is using {:.2}% of your CPU",
            process.cpu_usage
        );
        let output = Command::new("/usr/local/bin/alerter")
            .args(&["-title", &title])
            .args(&["-message", &message])
            .args(&["-actions", KILL])
            .args(&["-group", NOTIFIER_ID])
            .args(&["-closeLabel", IGNORE])
            .args(&["-appIcon", NOTIFICATION_ICON])
            .args(&["-json"])
            .args(&["-timeout", &NOTIFICATION_TIMEOUT.to_string()])
            .output()
            .expect("Failed to post notification");

        let notification: Notification = serde_json::from_slice(&output.stdout).unwrap();
        match &*notification.activationType {
            ACTION_CLICKED => {
                if let Some(value) = notification.activationValue {
                    match &*value {
                        KILL => {
                            process.kill(Signal::Kill);
                        }
                        _ => {}
                    }
                }
            }
            CLOSED => {
                self.ignore(process);
                self.dump_cache();
            }
            TIMEOUT => self.process_timeout(process),
            _ => {}
        };
    }

    fn process_timeout(&mut self, process: &Process) {
        let pid = process.pid as usize;
        if self.timeouts[pid] >= TIMEOUTS_THRESHOLD {
            self.ignore(process);
            self.dump_cache();
            self.timeouts[pid] = 0;
        } else {
            self.timeouts[pid] += 1;
        }
    }

    fn process_should_be_ignored(&mut self, process: &Process) -> bool {
        let cmd = process.cmd.join(" ");
        match self.ignored.get(&process.exe) {
            Some(cmds) => cmds.len() >= 3 || cmds.contains(&cmd),
            None => false,
        }
    }

    fn process_is_hog(&mut self, process: &Process) -> bool {
        let pid = process.pid as usize;

        if self.process_should_be_ignored(process) {
            self.hogs[pid] = 0;
            return false;
        }

        if process.cpu_usage > CPU_USAGE_THRESHOLD {
            if self.hogs[pid] >= HOGS_THRESHOLD {
                self.hogs[pid] = 0;
                return true;
            }
            self.hogs[pid] += 1;
        } else {
            self.hogs[pid] = 0;
        }

        false
    }

    fn watch(&mut self) {
        let poll_seconds = time::Duration::from_secs(POLL_SECONDS);
        let mut sys = System::new();

        loop {
            sys.refresh_processes();
            let processes = sys.get_process_list();
            for (_, process) in processes.iter() {
                if self.process_is_hog(process) {
                    self.notify(process);
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
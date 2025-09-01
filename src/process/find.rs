pub fn find_pids_by_proc_name(needle: &str) -> Option<Vec<u32>> {
    let mut pids = Vec::new();

    for entry in match std::fs::read_dir("/proc") {
        Ok(x) => x,
        Err(e) => {
            println!("Error on /proc: {e}");
            return None;
        },
    } {
        let entry = match entry {
            Ok(x) => x,
            Err(e) => {
                println!("Entry error: {e}");
                return None;
            },
        };

        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if let Ok(pid) = file_name.parse::<u32>() {
            let comm = entry.path().join("comm");

            if let Ok(name) = std::fs::read_to_string(&comm) {
                let name = name.trim();
                if name.eq(needle) {
                    pids.push(pid);
                }
            }
        }
    }

    Some(pids)
}

pub fn find_pids_by_proc_name_contains(needle: &str) -> Option<Vec<u32>> {
    let mut pids = Vec::new();

    for entry in match std::fs::read_dir("/proc") {
        Ok(x) => x,
        Err(e) => {
            println!("Error on /proc: {e}");
            return None;
        },
    } {
        let entry = match entry {
            Ok(x) => x,
            Err(e) => {
                println!("Entry error: {e}");
                return None;
            },
        };

        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if let Ok(pid) = file_name.parse::<u32>() {
            let comm = entry.path().join("comm");

            if let Ok(name) = std::fs::read_to_string(&comm) {
                let name = name.trim();
                if name.contains(needle) {
                    pids.push(pid);
                }
            }
        }
    }

    Some(pids)
}

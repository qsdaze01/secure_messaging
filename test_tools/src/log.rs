use std::fs::File;
use std::io::Write;
use chrono::prelude::*;

pub fn write_log(text:String) {
    let mut file = File::create("log/output.txt").expect("Error opening file");
    
    let local_now: DateTime<Local> = Local::now();

    let text_to_write = [local_now.to_string(), " : ".to_string(), text].concat();

    let _ = file.write_all(text_to_write.as_bytes());

    let _ = file.flush();
}
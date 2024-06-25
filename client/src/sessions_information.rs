use std::{fs::{read_to_string, File}, io::Write};

pub fn write_sessions_information(id: String, session_number:String, key_signature_client: String, key_encryption_client: String, key_signature_server: String, key_encryption_server: String) {
    let mut file = File::create(["sessions/session_", &id.to_string(),".txt"].concat()).expect("Error opening file");
    
    let text_to_write = [id, "|".to_owned(), session_number, "|".to_owned(), key_signature_client, "|".to_owned(), key_encryption_client, "|".to_owned(), key_signature_server, "|".to_owned(), key_encryption_server].concat();

    let _ = file.write_all(text_to_write.as_bytes());

    let _ = file.flush();
}

pub fn read_sessions_information_client(id: String, sequence_number: String) -> (String, String) {
    let content = read_to_string(["sessions/session_", &id.to_string(),".txt"].concat()).expect("Error reading in session file");

    let lines = content.split("\n").collect::<Vec<&str>>();
    let mut selected_line = "";
    for line in lines {
        if line.contains(&sequence_number) {
            selected_line = line;
        }
    }
    let binding = selected_line.split("|").collect::<Vec<&str>>();
    return (binding[2].to_string(), binding[3].to_string());
}

pub fn read_sessions_information_server(id: String, sequence_number: String) -> (String, String) {
    let content = read_to_string(["sessions/session_", &id.to_string(),".txt"].concat()).expect("Error reading in session file");

    let lines = content.split("\n").collect::<Vec<&str>>();
    let mut selected_line = "";
    for line in lines {
        if line.contains(&sequence_number) {
            selected_line = line;
        }
    }
    let binding = selected_line.split("|").collect::<Vec<&str>>();
    return (binding[4].to_string(), binding[5].to_string());
}

pub fn get_session_number(id: String) -> String {
    let content = read_to_string(["sessions/session_", &id.to_string(),".txt"].concat()).expect("Error reading in session file");
    let lines = content.split("\n").collect::<Vec<&str>>();

    let selected_line = lines[lines.len()-1];
    let binding = selected_line.split("|").collect::<Vec<&str>>();
    return binding[1].to_string();
}
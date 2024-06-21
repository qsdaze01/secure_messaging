use chrono::{NaiveDate, NaiveDateTime, Timelike};

pub struct Message {
    pub destination : String,
    pub source : String,
    pub message : String,
    pub message_len : usize,
    pub timestamp : NaiveDateTime,
    pub signature : String,
}

pub fn get_message_to_send(message: Message) -> String {
    return [message.destination, "|".to_owned(), message.source, "|".to_owned(), message.message, "|".to_owned(), message.message_len.to_string(), "|".to_owned(), message.timestamp.to_string(), "|".to_owned(), message.signature].concat();
}

pub fn receive_string_to_message(received_message: String) {
    let res = received_message.split("|").collect::<Vec<&str>>();

    let time_str = format!("1970-01-01 {}", res[4]);
    let timestamp = NaiveDateTime::parse_from_str(&time_str, "%Y-%m-%d %H:%M:%S").expect("Erreur lors du parsing du timestamp");

    let message = Message{
        destination: res[0].to_owned(),
        source: res[1].to_owned(),
        message: res[2].to_owned(),
        message_len: res[3].to_owned().parse::<usize>().unwrap(),
        timestamp: timestamp,
        signature: res[5].to_owned(),

    };
    println!("Received message : {:?}", res);
}
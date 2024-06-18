use num_bigint::BigUint;

use crate::{rsaes_oaep::RsaKey, utils::hex_string_to_biguint};
use rusqlite::Connection;

#[derive(Debug)]
pub struct IDClient {
    id: String,
    key_n: String,
    key_e: String
}

pub fn write_db_id(id:String, key: &RsaKey) {
    let conn = Connection::open("./data_base/id_database.db").expect("Error connection");

    let _ = match conn.execute(
        "CREATE TABLE clients (
            id   TEXT NOT NULL,
            key_n TEXT NOT NULL,
            key_e TEXT NOT NULL
        )",
        (), // empty list of parameters.
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("Database already created");
            Err(e)
        }
    };

    let client = IDClient {
        id: id.clone(),
        key_n: key.public_key.0.to_string(),
        key_e: key.public_key.1.to_string()
    };

    conn.execute(
        "INSERT INTO clients (id, key_n, key_e) VALUES (?1, ?2, ?3)",
        (&id, &client.key_n, &client.key_e),
    ).expect("Error Insert");

    let _ = conn.backup(rusqlite::DatabaseName::Attached("id_database"), "./data_base/id_database.db", None);
}

pub fn find_db_id(id:String) -> Option<RsaKey> {
    let conn = Connection::open("./data_base/id_database.db").expect("Error connection");

    let mut stmt = conn.prepare(&("SELECT id, key_n, key_e FROM clients WHERE id='".to_owned() + &id + "'")).expect("Error select");
    let clients_iter = stmt.query_map([], |row| {
        Ok(IDClient {
            id: row.get(0)?,
            key_n: row.get(1)?,
            key_e: row.get(2)?,
        })
    }).expect("Error mapping row");

    for client in clients_iter {
        match client {
            Ok(client) => {println!("Found person {:?}", client);
                let key = RsaKey{
                    private_key: BigUint::from(0u32),
                    public_key: (hex_string_to_biguint(&client.key_n), hex_string_to_biguint(&client.key_e))
                };
                return Some(key);
            },
            Err(err) => eprintln!("Erreur lors de la lecture des données: {}", err),
        }
    }
    None
}

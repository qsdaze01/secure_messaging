use num_bigint::BigUint;

use crate::{rsaes_oaep::RsaKey, utils::hex_string_to_biguint};
use rusqlite::Connection;

#[derive(Debug)]
pub struct IDClient {
    id: String,
    key_challenge_n: String,
    key_challenge_e: String,
    key_encryption_n: String,
    key_encryption_e: String,
}

pub fn write_db_id(id:String, key_challenge: &RsaKey, key_encryption: &RsaKey) {
    let conn = Connection::open("./data_base/id_database.db").expect("Error connection");

    let _ = match conn.execute(
        "CREATE TABLE clients (
            id   TEXT NOT NULL,
            key_challenge_n TEXT NOT NULL,
            key_challenge_e TEXT NOT NULL,
            key_encryption_n TEXT NOT NULL, 
            key_encryption_e TEXT NOT NULL
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
        key_challenge_n: key_challenge.public_key.0.to_string(),
        key_challenge_e: key_challenge.public_key.1.to_string(),
        key_encryption_n: key_encryption.public_key.0.to_string(),
        key_encryption_e: key_encryption.public_key.1.to_string()
    };

    conn.execute(
        "INSERT INTO clients (id, key_n, key_e) VALUES (?1, ?2, ?3)",
        (&id, &client.key_challenge_n, &client.key_challenge_e, &client.key_encryption_n, &client.key_encryption_e),
    ).expect("Error Insert");

    let _ = conn.backup(rusqlite::DatabaseName::Attached("id_database"), "./data_base/id_database.db", None);
}

pub fn find_db_id(id:String) -> Option<(RsaKey, RsaKey)> {
    let conn = Connection::open("./data_base/id_database.db").expect("Error connection");

    let mut stmt = conn.prepare(&("SELECT id, key_n, key_e FROM clients WHERE id='".to_owned() + &id + "'")).expect("Error select");
    let clients_iter = stmt.query_map([], |row| {
        Ok(IDClient {
            id: row.get(0)?,
            key_challenge_n: row.get(1)?,
            key_challenge_e: row.get(2)?,
            key_encryption_n: row.get(3)?,
            key_encryption_e: row.get(4)?,
        })
    }).expect("Error mapping row");

    for client in clients_iter {
        match client {
            Ok(client) => {println!("Found person {:?}", client);
                let key_challenge = RsaKey{
                    private_key: BigUint::from(0u32),
                    public_key: (hex_string_to_biguint(&client.key_challenge_n), hex_string_to_biguint(&client.key_challenge_e))
                };
                let key_encryption = RsaKey{
                    private_key: BigUint::from(0u32),
                    public_key: (hex_string_to_biguint(&client.key_encryption_n), hex_string_to_biguint(&client.key_encryption_e))
                };
                return Some((key_challenge, key_encryption));
            },
            Err(err) => eprintln!("Erreur lors de la lecture des données: {}", err),
        }
    }
    None
}

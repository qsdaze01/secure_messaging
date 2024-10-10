pub mod aes;
pub mod utils;
pub mod hmac;
pub mod log;
pub mod challenge;
pub mod identify_db;
pub mod cts_cbc;
pub mod pbkdf2;
pub mod message;
pub mod rsaes_oaep;
pub mod auth;
pub mod send_receive;
pub mod sessions_information;

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use auth::auth_client;
use identify_db::write_db_id;
use log::write_log;
use num_bigint::BigUint;
use num_traits::Num;
use rsaes_oaep::{key_generation, RsaKey};

fn handle_client(mut stream: TcpStream, key_challenge: &RsaKey, key_encryption: &RsaKey) {
    println!("Got client");
    if !auth_client(&mut stream, key_challenge, key_encryption) {
        write_log("Auth failed : next client".to_owned());
        println!("Failed");
        return;
    }

    println!("OK");

    /*
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                write_log("Close connexion".to_owned());
                break;
            }
            Ok(n) => {
                // Écrire les données reçues sur la sortie standard
                write_log(["Received : ", &String::from_utf8_lossy(&buffer[..n])].concat());
                // Envoyer une réponse au client
                if let Err(e) = stream.write_all(b"ACK\n") {
                    write_log(["Erreur lors de l'envoi de la réponse : ", &e.to_string()].concat());
                    break;
                }
            }
            Err(e) => {
                write_log(["Erreur lors de la lecture : ", &e.to_string()].concat());
                break;
            }
        }
    }
    */
}

fn main() -> std::io::Result<()> {
    /* INIT */
    println!("Start");
    let listener = TcpListener::bind("127.0.0.1:7878")?;
    write_log("Serveur en écoute sur le port 7878".to_owned());
    //let rsa_key_challenge = Arc::new(key_generation());
    //let rsa_key_encryption = Arc::new(key_generation());

    let rsa_key_challenge = Arc::new(RsaKey {
        private_key: BigUint::from_str_radix("1946242457703126188027075624856407864760766035591001829376562558620653817336889256437927675428336447885336542462506498613403726155250399121323993199931952855785795345377377115544000759171769587616225170919521327190445575030017454966205417974479046672862661737653353748453020284560558394471655457057408465396009138978728148890021007554528972463564278591467954600837225993800096221187853033135928534100471141972023555773529713797299379027270284812099907283555374518014424455438968222566017800391580726625109758883018690756222777824193000535329120188279847469360384103437568093180216767366118424893095473406987337811713", 10).unwrap(),
        public_key: (BigUint::from_str_radix("6108759193031119778962186552979616965173674505485032897119338141969434349942898045937378642938069242579564223341249444426563218440452366245891309499230861796438394135536262644703408896256717598831635489777426686785451707411027487841005961580145272116829514477997502136607547432435120474065559563657633074552759929888804888945716072812939903147734323536332785503476002653297987509796470729388897458353767575865713487045665284316848299228347748837794591518242160126033073713264431058996904566215523803395017807126601667270939055171404141158517829163897954946072896088615025964244750561131216610406796504086829315838827", 10).unwrap(), BigUint::from(65537u32)),
    });
    let rsa_key_encryption = Arc::new(RsaKey {
        private_key: BigUint::from_str_radix("678657167054936286930596157320565222844573632567372412909519325031476583141030326039070291188080713473166853807198300046768138993699737028147188994255189986798308608177184072980519648511393906081033121269794177038614164982448984995671182162434705502729663438703467513618747184341153164954481743840052477965365097610588718147625042069605392500161548974928431217683566591807553728586899158741428220339642930018713140428397915208544554802765372713494620436623382568347970428365268653953067329724545268711970129163911946013727306394976372099315776120216865434821864608994027970493359226290684312829138902117855903035233", 10).unwrap(),
        public_key: (BigUint::from_str_radix("693654940069859005560986905213940783056219933836055611741284591462693088417244299401474573823974512147394511820997426546554016301155640449371215301255495729332513275953027332983847726208534348453410288032727713359008991429425438703388993533678778766880754098289288060512037339678199547280440892795469732508118011121053586525291400306334458615674941372881366948675409882570579787185423224508730113405321364719057883944778343603665095993437744106983825036146032030969226126263569821455255120175624389690128137366781051944318111411493493582574486991906144405268321505121417576066489946273986545948145782124007052750377", 10).unwrap(), BigUint::from(65537u32)),
    });

    //println!("Challenge : {:?}", rsa_key_challenge);
    //println!("Encryption : {:?}", rsa_key_encryption);

    write_db_id("server_rsa_keys".to_owned(), &rsa_key_challenge, &rsa_key_encryption);

    println!("Ready to listen");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rsa_key_challenge_clone = Arc::clone(&rsa_key_challenge);
                let rsa_key_encryption_clone = Arc::clone(&rsa_key_encryption);
                thread::spawn(move || handle_client(stream, &rsa_key_challenge_clone, &rsa_key_encryption_clone));
            }
            Err(e) => {
                eprintln!("Erreur lors de la connexion : {}", e);
            }
        }
    }

    Ok(())
}

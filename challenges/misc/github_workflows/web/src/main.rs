use rocket::FromForm;
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::get;
use rocket::http::Status;
use rocket::launch;
use rocket::post;
use rocket::routes;
use rocket::serde::json::Json;
use rocket::{Build, Rocket};
use serde::Serialize;
use std::path::Path;
use std::process::Command;

#[derive(Serialize)]
struct CreateResponse {
    url: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type ApiResponse = Result<Json<CreateResponse>, (Status, Json<ErrorResponse>)>;

async fn github_user_exists(username: &str) -> Result<bool, String> {
    let client = reqwest::Client::new();
    let url = format!("https://api.github.com/users/{}", username);

    let response = client
        .get(&url)
        .header("User-Agent", "rust-reqwest")
        .send()
        .await
        .map_err(|e| format!("Failed to send request to GitHub API: {}", e))?;

    match response.status() {
        reqwest::StatusCode::OK => Ok(true),
        reqwest::StatusCode::NOT_FOUND => Ok(false),
        _ => Err(format!(
            "GitHub API returned an unexpected status: {}",
            response.status()
        )),
    }
}

struct EnvVar {
    org: String,
    repo: String,
    bundle: String,
    admin_pat: String,
    script_path: String,
}

impl EnvVar {
    fn run_local_script(&self, username: &str) -> Result<String, String> {
        let output = Command::new(self.script_path.as_str())
            .args(&[
                "--org",
                self.org.as_str(),
                "--repo",
                self.repo.as_str(),
                "--bundle",
                self.bundle.as_str(),
                "--action",
                "create",
                "--flag",
                "FLAG_BANGLADESH=flag-bangladesh-ec1ec9022f3c",
                "--flag",
                "FLAG_EGYPT=flag-egypt-9312131bb234",
                "--flag",
                "FLAG_INDONESIA=flag-indonesia-68a79b1c7d55",
                "--flag",
                "FLAG_IRAN=flag-iran-e8aad09cfa0a",
                "--username",
                username,
            ])
            .output()
            .map_err(|e| format!("Failed to execute script: {}", e))?;

        if output.status.success() {
            String::from_utf8(output.stdout)
                .map_err(|e| format!("Script output was not valid UTF-8: {}", e))
                .map(|s| s.trim().to_string())
        } else {
            let error_message = String::from_utf8_lossy(&output.stderr);
            Err(format!("Script execution failed: {}", error_message))
        }
    }
}

#[derive(FromForm)]
struct UsernameForm {
    username: String,
}

#[post("/create", data = "<form>")]
async fn create_form(form: Form<UsernameForm>) -> ApiResponse {
    let username = &form.username;
    if username.is_empty() {
        return Err((
            Status::BadRequest,
            Json(ErrorResponse {
                error: "Username cannot be empty.".to_string(),
            }),
        ));
    }

    // check contains only alphanumeric characters and hyphens
    if !username.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err((
            Status::BadRequest,
            Json(ErrorResponse {
                error: "Username can only contain alphanumeric characters and hyphens.".to_string(),
            }),
        ));
    }

    match github_user_exists(username).await {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                Status::NotFound,
                Json(ErrorResponse {
                    error: format!("GitHub user '{}' not found.", username),
                }),
            ));
        }
        Err(e) => {
            return Err((
                Status::InternalServerError,
                Json(ErrorResponse { error: e }),
            ));
        }
    }

    let env = EnvVar {
        org: env::var("ORG_NAME")
            .expect("ORG_NAME not defined")
            .to_string(),
        repo: env::var("REPO_NAME")
            .expect("REPO_NAME not defined")
            .to_string(),
        bundle: env::var("BUNDLE_PATH")
            .expect("BUNDLE_PATH not defined")
            .to_string(),
        admin_pat: env::var("GH_TOKEN")
            .expect("GH_TOKEN not defined")
            .to_string(),
        script_path: env::var("SCRIPT_PATH")
            .expect("SCRIPT_PATH not defined")
            .to_string(),
    };

    let api_url = format!(
        "https://api.github.com/repos/{}/{}-{}",
        env.org, env.repo, username
    );
    let url = format!("https://github.com/{}/{}-{}", env.org, env.repo, username);

    // check if the url already exists
    let client = reqwest::Client::new();
    let response = client
        .get(&api_url)
        .header("User-Agent", "rust-reqwest")
        .header("Authorization", format!("Bearer {}", env.admin_pat))
        .send()
        .await;
    match response {
        Ok(resp) => {
            if resp.status() == reqwest::StatusCode::OK {
                return Ok(Json(CreateResponse { url }));
            }
        }
        Err(e) => {
            return Err((
                Status::InternalServerError,
                Json(ErrorResponse {
                    error: format!("Failed to check if the repo exists: {}", e),
                }),
            ));
        }
    }

    match env.run_local_script(username) {
        Ok(_) => Ok(Json(CreateResponse { url })),
        Err(e) => Err((
            Status::InternalServerError,
            Json(ErrorResponse { error: e }),
        )),
    }
}

#[get("/")]
async fn index() -> Option<NamedFile> {
    NamedFile::open(Path::new("static/index.html")).await.ok()
}

#[launch]
fn rocket() -> Rocket<Build> {
    rocket::build().mount("/", routes![create_form, index])
}


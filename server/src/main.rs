use std::{
    collections::HashMap,
    env,
    process::exit,
    sync::{Arc, Mutex},
};
use core::*;
use dotenv::dotenv;
use actix_web::{
    delete, get, patch, post,
    web::{self, Data},
    App, HttpResponse, HttpServer,
};

#[actix_web::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    // Load .env or exit if it fails
    dotenv().unwrap_or_else(|x| {
        println!("Could not load .env file: {}", x);
        exit(1);
    });
    // Create an auth object and store it in an ARC
    let auth = Arc::new(Mutex::new(
        init_auth(
            match env::var("POSTGRES_URL") {
                Ok(url) => url,
                Err(_) => {
                    println!("No POSTGRES_URL env var found, using default");
                    "postgresql://postgres:postgres@localhost:5432".to_string()
                }
            },
            match env::var("REDIS_URL") {
                Ok(url) => url,
                Err(_) => {
                    println!("No REDIS_URL env var found, using default");
                    "postgresql://postgres:postgres@localhost:5432".to_string()
                }
            },
        )
        .await
        .unwrap_or_else(|x| {
            println!("Could not initialize auth: {}", x.to_error_message());
            exit(1);
        }),
    ));
    // Create the server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(Arc::clone(&auth)))
            .service(login_handler)
            .service(logout_handler)
            .service(token_verify_handler)
            .service(register_handler)
            .service(update_user_handler)
            .service(admin_update_user_handler)
            .service(delete_user_handler)
            .service(admin_delete_user_handler)
    })
    .bind(("127.0.0.1", 8080))
    .unwrap()
    .run()
    .await
    .unwrap();
}

// Handlers for the web server

#[post("/login")]
pub(crate) async fn login_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    login_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let login_data = login_data.into_inner();
    let email = match login_data["email"] {
        serde_json::Value::String(ref email) => email,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let password = match login_data["password"] {
        serde_json::Value::String(ref password) => password,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match login(&mut auth, email.clone(), password.clone()).await {
        Ok(x) => HttpResponse::Ok().body(x),
        Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
    }
}

#[post("/logout")]
pub(crate) async fn logout_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    logout_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let logout_data = logout_data.into_inner();
    let token = match logout_data["token"] {
        serde_json::Value::String(ref token) => token,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match logout(&mut auth, token.clone()) {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
    }
}

#[get("/token")]
pub(crate) async fn token_verify_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    token_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let token_data = token_data.into_inner();
    let token = match token_data["token"] {
        serde_json::Value::String(ref token) => token,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match verify_token(&mut auth, token.clone()).await {
        Ok(x) => {
            if x != "" {
                HttpResponse::Ok().json(HashMap::from([("email", x)]))
            } else {
                HttpResponse::BadRequest()
                    .json(HashMap::from([("error", "Invalid token".to_string())]))
            }
        }
        Err(x) => HttpResponse::BadRequest().json(HashMap::from([("error", x.to_error_message())])),
    }
}

#[post("/user")]
pub(crate) async fn register_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    register_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let register_data = register_data.into_inner();
    let email = match register_data["email"] {
        serde_json::Value::String(ref email) => email,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let password = match register_data["password"] {
        serde_json::Value::String(ref password) => password,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match create_user(&mut auth, email.clone(), password.clone()).await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
    }
}

#[patch("/user")]
pub(crate) async fn update_user_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    update_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let update_data = update_data.into_inner();
    let token = match update_data["token"] {
        serde_json::Value::String(ref token) => token,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let email = match update_data["email"] {
        serde_json::Value::String(ref email) => Some(email.clone()),
        serde_json::Value::Null => None,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let password = match update_data["password"] {
        serde_json::Value::String(ref password) => Some(password.clone()),
        serde_json::Value::Null => None,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let logout = match update_data["logout"] {
        serde_json::Value::Bool(ref logout) => Some(*logout),
        serde_json::Value::Null => None,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match update_user(
        &mut auth,
        token.clone(),
        email,
        password,
        logout.unwrap_or(false),
    )
    .await
    {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
    }
}

#[delete("/user")]
pub(crate) async fn delete_user_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    delete_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let delete_data = delete_data.into_inner();
    let token = match delete_data["token"] {
        serde_json::Value::String(ref token) => token,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match delete_user(&mut auth, token.clone()).await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
    }
}

#[patch("/admin/user")]
pub(crate) async fn admin_update_user_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    update_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let update_data = update_data.into_inner();
    let filter = match update_data["filter"] {
        serde_json::Value::String(ref token) => token,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let email = match update_data["email"] {
        serde_json::Value::String(ref email) => Some(email.clone()),
        serde_json::Value::Null => None,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let password = match update_data["password"] {
        serde_json::Value::String(ref password) => Some(password.clone()),
        serde_json::Value::Null => None,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let logout = match update_data["logout"] {
        serde_json::Value::Bool(ref logout) => Some(*logout),
        serde_json::Value::Null => None,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match admin_update_user(
        &mut auth,
        filter.clone(),
        email,
        password,
        logout.unwrap_or(false),
    )
    .await
    {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
    }
}

#[delete("/admin/user")]
pub(crate) async fn admin_delete_user_handler(
    auth_data: Data<Arc<Mutex<Auth>>>,
    delete_data: web::Json<HashMap<String, serde_json::Value>>,
) -> HttpResponse {
    let delete_data = delete_data.into_inner();
    let filter = match delete_data["filter"] {
        serde_json::Value::String(ref token) => token,
        _ => return HttpResponse::BadRequest().finish(),
    };
    let mut auth = auth_data.lock().unwrap();
    match admin_delete_user(&mut auth, filter.clone()).await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
    }
}

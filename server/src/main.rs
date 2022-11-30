use core::{init_auth, AuthError};
use std::{
    env,
    process::exit,
    sync::{Arc, Mutex},
};

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
        init_auth(match env::var("POSTGRES_URL") {
            Ok(url) => url,
            Err(_) => {
                println!("No POSTGRES_URL env var found, using default");
                "postgresql://postgres:postgres@localhost:5432".to_string()
            }
        })
        .await
        .unwrap_or_else(|x| {
            println!("Could not initialize auth: {}", to_error_message(&x));
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

// Convert an AuthError to an error message string
pub fn to_error_message(err: &AuthError) -> &'static str {
    const SERVER_SIDE_ERROR_MESSAGE: &str =
        "An error occured while processing your request. Please try again later.";
    match err {
        AuthError::UserAlreadyExists => "User already exists",
        AuthError::UserDoesNotExist => "User does not exist",
        AuthError::IncorrectUsernameOrPassword => "Incorrect username or password",
        AuthError::InvalidToken => "Invalid token",
        AuthError::TokenDoesNotExist => "Token does not exist",
        AuthError::UnableToAquireTokenListLock => SERVER_SIDE_ERROR_MESSAGE,
        AuthError::DatabaseError(_) => SERVER_SIDE_ERROR_MESSAGE,
    }
}

// Structs for the handlers to represent JSON data in the request body
mod data_structs {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub(crate) struct LoginData {
        pub email: String,
        pub password: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct LogoutData {
        pub token: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct TokenVerifyData {
        pub token: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct RegisterData {
        pub email: String,
        pub password: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct UpdateUserData {
        pub token: String,
        pub filter: String,
        pub email: Option<String>,
        pub password: Option<String>,
    }

    #[derive(Deserialize)]
    pub(crate) struct AdminUpdateUserData {
        pub filter: String,
        pub email: Option<String>,
        pub password: Option<String>,
    }

    #[derive(Deserialize)]
    pub(crate) struct DeleteUserData {
        pub token: String,
        pub filter: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct AdminDeleteUserData {
        pub filter: String,
    }
}
use data_structs::*;

// Handlers for the web server
mod handlers {
    use core::*;

    use crate::*;

    #[post("/login")]
    pub(crate) async fn login_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        login_data: web::Json<LoginData>,
    ) -> HttpResponse {
        let login_data = login_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match login(&mut auth, login_data.email, login_data.password).await {
            Ok(x) => HttpResponse::Ok().body(x),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }

    #[post("/logout")]
    pub(crate) async fn logout_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        logout_data: web::Json<LogoutData>,
    ) -> HttpResponse {
        let mut auth = auth_data.lock().unwrap();
        let logout_data = logout_data.into_inner();
        match logout(&mut auth, logout_data.token) {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }

    #[get("/token")]
    pub(crate) async fn token_verify_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        token_data: web::Json<TokenVerifyData>,
    ) -> HttpResponse {
        let auth = auth_data.lock().unwrap();
        let token_data = token_data.into_inner();
        match verify_token(&auth, token_data.token).await {
            Ok(x) => HttpResponse::Ok().body(if x { "valid" } else { "invalid" }),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }

    #[post("/user")]
    pub(crate) async fn register_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        register_data: web::Json<RegisterData>,
    ) -> HttpResponse {
        let register_data = register_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match create_user(&mut auth, register_data.email, register_data.password).await {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }

    #[patch("/user")]
    pub(crate) async fn update_user_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        update_data: web::Json<UpdateUserData>,
    ) -> HttpResponse {
        let update_data = update_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match update_user(
            &mut auth,
            update_data.token,
            update_data.filter,
            update_data.email,
            update_data.password,
        )
        .await
        {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }

    #[delete("/user")]
    pub(crate) async fn delete_user_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        delete_data: web::Json<DeleteUserData>,
    ) -> HttpResponse {
        let delete_data = delete_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match delete_user(&mut auth, delete_data.token, delete_data.filter).await {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }

    #[patch("/admin/user")]
    pub(crate) async fn admin_update_user_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        update_data: web::Json<AdminUpdateUserData>,
    ) -> HttpResponse {
        let update_data = update_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match admin_update_user(
            &mut auth,
            update_data.filter,
            update_data.email,
            update_data.password,
        )
        .await
        {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }

    #[delete("/admin/user")]
    pub(crate) async fn admin_delete_user_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        delete_data: web::Json<AdminDeleteUserData>,
    ) -> HttpResponse {
        let delete_data = delete_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match admin_delete_user(&mut auth, delete_data.filter).await {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(to_error_message(&x)),
        }
    }
}
use dotenv::dotenv;
use handlers::*;

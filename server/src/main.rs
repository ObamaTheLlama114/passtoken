use core::init_auth;
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
        pub email: Option<String>,
        pub password: Option<String>,
        pub logout: Option<bool>,
    }

    #[derive(Deserialize)]
    pub(crate) struct AdminUpdateUserData {
        pub filter: String,
        pub email: Option<String>,
        pub password: Option<String>,
        pub logout: Option<bool>,
    }

    #[derive(Deserialize)]
    pub(crate) struct DeleteUserData {
        pub token: String,
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
    use std::collections::HashMap;

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
            Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
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
            Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
        }
    }

    #[get("/token")]
    pub(crate) async fn token_verify_handler(
        auth_data: Data<Arc<Mutex<Auth>>>,
        token_data: web::Json<TokenVerifyData>,
    ) -> HttpResponse {
        let mut auth = auth_data.lock().unwrap();
        let token_data = token_data.into_inner();
        match verify_token(&mut auth, token_data.token).await {
            Ok(x) => {
                if x != "" {
                    HttpResponse::Ok().json(HashMap::from([("email", x)]))
                } else {
                    HttpResponse::BadRequest()
                        .json(HashMap::from([("error", "Invalid token".to_string())]))
                }
            }
            Err(x) => {
                HttpResponse::BadRequest().json(HashMap::from([("error", x.to_error_message())]))
            }
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
            Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
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
            update_data.email,
            update_data.password,
            update_data.logout.unwrap_or(false),
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
        delete_data: web::Json<DeleteUserData>,
    ) -> HttpResponse {
        let delete_data = delete_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match delete_user(&mut auth, delete_data.token).await {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
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
            update_data.logout.unwrap_or(false),
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
        delete_data: web::Json<AdminDeleteUserData>,
    ) -> HttpResponse {
        let delete_data = delete_data.into_inner();
        let mut auth = auth_data.lock().unwrap();
        match admin_delete_user(&mut auth, delete_data.filter).await {
            Ok(_) => HttpResponse::Ok().body(""),
            Err(x) => HttpResponse::BadRequest().body(x.to_error_message()),
        }
    }
}
use dotenv::dotenv;
use handlers::*;

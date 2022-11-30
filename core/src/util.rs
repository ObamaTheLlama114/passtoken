use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use super::error::AuthError;

pub type TokenList = Arc<Mutex<HashMap<String, (i32, i32)>>>;

pub(crate) async fn get_pool(postgres_url: String) -> Result<Pool<Postgres>, AuthError> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&postgres_url)
        .await
        .or_else(|x| Err(AuthError::DatabaseError(x)))?;
    init_db(&pool).await.unwrap();
    Ok(pool)
}

pub(crate) async fn init_db(pool: &Pool<Postgres>) -> Result<(), AuthError> {
    match sqlx::query!(
        r#"CREATE TABLE IF NOT EXISTS "users" (
        id INT GENERATED ALWAYS AS IDENTITY,
        email TEXT NOT NULL UNIQUE,
        passwordhash TEXT NOT NULL,
        salt TEXT NOT NULL
        );"#
    )
    .execute(pool)
    .await
    {
        Ok(ok) => ok,
        Err(err) => return Err(AuthError::DatabaseError(err)),
    };
    Ok(())
}

pub(crate) fn hash(password: String, salt: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password + &salt[..]);
    format!("{:X}", hasher.finalize())
}

pub(crate) async fn connect(
    pool: &Pool<Postgres>,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, AuthError> {
    match pool.acquire().await {
        Ok(conn) => Ok(conn),
        Err(err) => Err(AuthError::DatabaseError(err)),
    }
}

pub(crate) fn generate_token(token_list: &TokenList) -> Result<String, AuthError> {
    let mut token = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    while token_list
        .lock()
        .or(Err(AuthError::UnableToAquireTokenListLock))?
        .contains_key(&token)
    {
        token = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
    }
    Ok(token)
}

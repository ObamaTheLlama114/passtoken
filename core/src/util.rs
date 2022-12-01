use rand::{distributions::Alphanumeric, Rng};
use redis::Commands;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use super::error::AuthError;

pub(crate) async fn get_pool(postgres_url: String) -> Result<Pool<Postgres>, AuthError> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&postgres_url)
        .await
        .or_else(|x| Err(AuthError::PostgresError(x)))?;
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
        Err(err) => return Err(AuthError::PostgresError(err)),
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
        Err(err) => Err(AuthError::PostgresError(err)),
    }
}

pub(crate) fn generate_token(redis: &mut redis::Client) -> Result<String, AuthError> {
    let mut token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    while redis
        .get(token.clone())
        .or_else(|x| Err(AuthError::RedisError(x)))
        .and_then(|x: Option<i32>| Ok(x.is_some()))?
    {
        token = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
    }
    Ok(token)
}

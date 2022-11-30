use std::env;

use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tokio::runtime::Runtime;

fn main() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        dotenv().ok();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(env::var("DATABASE_URL").unwrap().as_str())
            .await
            .unwrap();
        sqlx::query!(
            r#"CREATE TABLE IF NOT EXISTS "users" (
                id INT GENERATED ALWAYS AS IDENTITY,
                email TEXT NOT NULL UNIQUE,
                passwordhash TEXT NOT NULL,
                salt TEXT NOT NULL
            );"#
        )
        .execute(&pool)
        .await
        .unwrap();
    });
}

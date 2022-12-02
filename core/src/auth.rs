use rand::{distributions::Alphanumeric, Rng};
use redis::Commands;
use sqlx::{Pool, Postgres};

use crate::{
    util::{self, connect, generate_token, hash},
    AuthError,
};

#[derive(Clone)]
pub struct Auth {
    redis: redis::Client,
    postgres: Pool<Postgres>,
    pub token_expire_time: Option<usize>,
}

impl Auth {
    pub fn token_expire_time(mut self, token_expire_time: Option<usize>) -> Self {
        self.token_expire_time = token_expire_time;
        self
    }
}

pub async fn init_auth(postgres_url: String, redis_url: String) -> Result<Auth, AuthError> {
    let postgres = util::get_pool(postgres_url).await?;
    util::init_db(&postgres).await?;
    let redis = redis::Client::open(redis_url).or_else(|x| Err(AuthError::RedisError(x)))?;
    Ok(Auth {
        redis,
        postgres,
        token_expire_time: None,
    })
}

pub async fn create_user(
    auth: &mut Auth,
    email: String,
    password: String,
) -> Result<(), AuthError> {
    // make sure email is not already in use
    match get_user_by_email(auth, email.clone()).await {
        Err(AuthError::UserDoesNotExist) => {}
        Err(AuthError::PostgresError(dberr)) => return Err(AuthError::PostgresError(dberr)),
        Ok(_) => return Err(AuthError::UserAlreadyExists),
        Err(err) => return Err(err),
    };

    // get hash and salt
    let salt: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();
    let passwordhash = hash(password.clone(), salt.clone());

    // create user
    match sqlx::query!(
        r#"
        INSERT INTO users ( email, passwordhash, salt )
        VALUES ( $1, $2, $3 );
        "#,
        email,
        passwordhash,
        salt
    )
    .execute(&auth.postgres)
    .await
    {
        Ok(ok) => ok,
        Err(err) => return Err(AuthError::PostgresError(err)),
    };
    Ok(())
}

async fn get_user_by_email(
    auth: &Auth,
    email: String,
) -> Result<(i32, String, String, String), AuthError> {
    let mut conn = connect(&auth.postgres).await?;
    match sqlx::query!(
        r#"
        SELECT *
        FROM users
        WHERE email = $1;
        "#,
        email
    )
    .fetch_optional(&mut conn)
    .await
    {
        Ok(Some(user)) => Ok((user.id, user.email, user.passwordhash, user.salt)),
        Ok(None) => Err(AuthError::UserDoesNotExist),
        Err(err) => Err(AuthError::PostgresError(err)),
    }
}

async fn get_user_by_id(auth: &Auth, id: i32) -> Result<(i32, String, String, String), AuthError> {
    let mut conn = connect(&auth.postgres).await?;
    match sqlx::query!(
        r#"
        SELECT *
        FROM users
        WHERE id = $1;
        "#,
        id
    )
    .fetch_optional(&mut conn)
    .await
    {
        Ok(Some(user)) => Ok((user.id, user.email, user.passwordhash, user.salt)),
        Ok(None) => Err(AuthError::UserDoesNotExist),
        Err(err) => Err(AuthError::PostgresError(err)),
    }
}

async fn update_user_by_email(
    auth: &Auth,
    filter: String,
    email: Option<String>,
    password: Option<String>,
) -> Result<(), AuthError> {
    let mut conn = connect(&auth.postgres).await?;

    // Check if user exists
    match get_user_by_email(auth, filter.clone()).await {
        Ok(_) => {}
        Err(AuthError::UserDoesNotExist) => return Err(AuthError::UserDoesNotExist),
        Err(AuthError::PostgresError(err)) => return Err(AuthError::PostgresError(err)),
        _ => unreachable!(),
    };

    if let Some(email) = email.clone() {
        match sqlx::query!(
            r#"
            UPDATE "users"
            SET email   = $1
            WHERE email = $2;
            "#,
            email,
            filter
        )
        .execute(&mut conn)
        .await
        {
            Ok(ok) => ok,
            Err(err) => return Err(AuthError::PostgresError(err)),
        };
    };

    if let Some(password) = password {
        // get hash and salt
        let salt: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        let passwordhash = hash(password.clone(), salt.clone());
        match sqlx::query!(
            r#"
            UPDATE "users"
            SET passwordhash = $1,
                salt         = $2
            WHERE email      = $3;
            "#,
            passwordhash,
            salt,
            filter
        )
        .execute(&mut conn)
        .await
        {
            Ok(ok) => ok,
            Err(err) => return Err(AuthError::PostgresError(err)),
        };
    };

    Ok(())
}

async fn delete_user_by_email(auth: &Auth, filter: String) -> Result<(), AuthError> {
    let mut conn = connect(&auth.postgres).await?;

    // make sure user exists
    get_user_by_email(auth, filter.clone()).await?;

    match sqlx::query!(
        r#"
        DELETE FROM "users"
        WHERE email = $1;
        "#,
        filter
    )
    .execute(&mut conn)
    .await
    {
        Ok(_) => {}
        Err(err) => return Err(AuthError::PostgresError(err)),
    };

    Ok(())
}

fn get_id_from_token(auth: &mut Auth, token: String) -> Result<i32, AuthError> {
    auth.redis
        .get(&token) // get id from token
        .or_else(|x| Err(AuthError::RedisError(x)))
        .and_then(|id: Option<i32>| {
            if let Some(id) = id {
                Ok(id)
            } else {
                Err(AuthError::TokenDoesNotExist)
            }
        })
}

pub async fn login(auth: &mut Auth, email: String, password: String) -> Result<String, AuthError> {
    if !verify_user(auth, email.clone(), password.clone()).await? {
        return Err(AuthError::IncorrectUsernameOrPassword);
    }
    let token = generate_token(&mut auth.redis)?;
    let (id, _, _, _) = get_user_by_email(auth, email).await?;
    let _ = auth
        .redis
        .set(token.clone(), id)
        .or_else(|x| Err(AuthError::RedisError(x)))?;
    match auth.token_expire_time {
        Some(x) => {
            let _ = auth
                .redis
                .expire(token.clone(), x)
                .or_else(|x| Err(AuthError::RedisError(x)))?;
        }
        None => {}
    }
    Ok(token)
}

pub fn logout(auth: &mut Auth, token: String) -> Result<(), AuthError> {
    match auth
        .redis
        .del::<_, Option<i32>>(&token)
        .or_else(|x| Err(AuthError::RedisError(x)))?
    {
        Some(_) => Ok(()),
        None => Err(AuthError::TokenDoesNotExist),
    }
}

async fn delete_user_tokens(auth: &mut Auth, email: String) -> Result<(), AuthError> {
    let (id, _, _, _) = get_user_by_email(auth, email.clone()).await?;
    let keys: Vec<String> = auth
        .redis
        .keys("*")
        .or_else(|x| Err(AuthError::RedisError(x)))?;
    for x in keys {
        match auth.redis.get::<_, i32>(x.clone()) {
            Ok(y) => {
                if id == y {
                    match auth.redis.del::<_, i32>(x) {
                        Ok(_) => {}
                        Err(x) => {
                            return Err(AuthError::RedisError(x));
                        }
                    };
                }
            }
            Err(_) => {}
        }
    }
    Ok(())
}

pub async fn update_user(
    auth: &mut Auth,
    token: String,
    new_email: Option<String>,
    new_password: Option<String>,
    logout: bool,
) -> Result<(), AuthError> {
    let id = get_id_from_token(auth, token)?;
    let (_, email, _, _) = get_user_by_id(auth, id).await?;
    if logout {
        delete_user_tokens(auth, email.clone()).await?;
    }
    update_user_by_email(auth, email, new_email, new_password).await
}

pub async fn admin_update_user(
    auth: &mut Auth,
    filter: String,
    email: Option<String>,
    password: Option<String>,
    logout: bool,
) -> Result<(), AuthError> {
    if logout {
        delete_user_tokens(auth, filter.clone()).await?;
    }
    update_user_by_email(auth, filter, email, password).await
}

pub async fn delete_user(auth: &mut Auth, token: String) -> Result<(), AuthError> {
    let id = get_id_from_token(auth, token)?;
    let (_, email, _, _) = get_user_by_id(auth, id).await?;
    delete_user_tokens(auth, email.clone()).await?;
    delete_user_by_email(auth, email).await
}

pub async fn admin_delete_user(auth: &mut Auth, filter: String) -> Result<(), AuthError> {
    delete_user_tokens(auth, filter.clone()).await?;
    delete_user_by_email(auth, filter).await
}

async fn verify_user(auth: &mut Auth, email: String, password: String) -> Result<bool, AuthError> {
    let (_, _, passwordhash, salt) = get_user_by_email(auth, email).await?;
    if hash(password, salt) == passwordhash {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn verify_token(auth: &mut Auth, token: String) -> Result<String, AuthError> {
    match auth.redis.get::<_, Option<i32>>(token.clone()) {
        Ok(Some(id)) => {
            match auth.token_expire_time {
                Some(x) => {
                    let _ = auth
                        .redis
                        .expire(token.clone(), x)
                        .or_else(|x| Err(AuthError::RedisError(x)))?;
                }
                None => {}
            }
            Ok(get_user_by_id(auth, id).await?.1)
        }
        Ok(None) => Ok(String::from("")),
        Err(x) => Err(AuthError::RedisError(x)),
    }
}

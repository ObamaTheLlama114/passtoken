use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use rand::{distributions::Alphanumeric, Rng};
use sqlx::{Pool, Postgres};

use crate::{
    util::{self, connect, generate_token, hash},
    AuthError,
};

#[derive(Clone)]
pub struct Auth {
    token_list: Arc<Mutex<HashMap<String, (i32, i32)>>>,
    pool: Pool<Postgres>,
}

pub async fn init_auth(postgres_url: String) -> Result<Auth, AuthError> {
    let pool = util::get_pool(postgres_url).await?;
    util::init_db(&pool).await?;
    let token_list = Arc::new(Mutex::new(HashMap::new()));
    Ok(Auth { token_list, pool })
}

pub async fn create_user(
    auth: &mut Auth,
    email: String,
    password: String,
) -> Result<(), AuthError> {
    // make sure email is not already in use
    match get_user_by_email(auth, email.clone()).await {
        Err(AuthError::UserDoesNotExist) => {}
        Err(AuthError::DatabaseError(dberr)) => return Err(AuthError::DatabaseError(dberr)),
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
    .execute(&auth.pool)
    .await
    {
        Ok(ok) => ok,
        Err(err) => return Err(AuthError::DatabaseError(err)),
    };
    Ok(())
}

async fn get_user_by_email(
    auth: &Auth,
    email: String,
) -> Result<(i32, String, String, String), AuthError> {
    let mut conn = connect(&auth.pool).await?;
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
        Err(err) => Err(AuthError::DatabaseError(err)),
    }
}

async fn update_user_by_email(
    auth: &Auth,
    filter: String,
    email: Option<String>,
    password: Option<String>,
) -> Result<(), AuthError> {
    let mut conn = connect(&auth.pool).await?;

    // Check if user exists
    match get_user_by_email(auth, filter.clone()).await {
        Ok(_) => {}
        Err(AuthError::UserDoesNotExist) => return Err(AuthError::UserDoesNotExist),
        Err(AuthError::DatabaseError(err)) => return Err(AuthError::DatabaseError(err)),
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
            Err(err) => return Err(AuthError::DatabaseError(err)),
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
            Err(err) => return Err(AuthError::DatabaseError(err)),
        };
    };

    Ok(())
}

async fn delete_user_by_email(auth: &Auth, filter: String) -> Result<(), AuthError> {
    let mut conn = connect(&auth.pool).await?;

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
        Err(err) => return Err(AuthError::DatabaseError(err)),
    };

    Ok(())
}

fn get_id_from_token(auth: &Auth, token: String) -> Result<i32, AuthError> {
    let token_list = auth
        .token_list
        .lock()
        .or(Err(AuthError::UnableToAquireTokenListLock))?;
    match token_list.get(&token) {
        Some(token) => Ok(token.0),
        None => Err(AuthError::TokenDoesNotExist),
    }
}

pub async fn login(auth: &mut Auth, email: String, password: String) -> Result<String, AuthError> {
    if !verify_user(auth, email.clone(), password.clone()).await? {
        return Err(AuthError::IncorrectUsernameOrPassword);
    }
    let token = generate_token(&auth.token_list)?;
    let (id, _, _, _) = get_user_by_email(auth, email).await?;
    let _ = auth
        .token_list
        .lock()
        .or(Err(AuthError::UnableToAquireTokenListLock))?
        .insert(token.clone(), (id, 0));
    Ok(token)
}

pub fn logout(auth: &mut Auth, token: String) -> Result<(), AuthError> {
    let mut token_list = auth
        .token_list
        .lock()
        .or(Err(AuthError::UnableToAquireTokenListLock))?;
    match token_list.remove(&token) {
        Some(_) => Ok(()),
        None => Err(AuthError::TokenDoesNotExist),
    }
}

pub async fn update_user(
    auth: &Auth,
    token: String,
    filter: String,
    email: Option<String>,
    password: Option<String>,
) -> Result<(), AuthError> {
    let (id, _, _, _) = get_user_by_email(auth, filter.clone()).await?;
    if id != get_id_from_token(auth, token)? {
        return Err(AuthError::InvalidToken);
    }
    update_user_by_email(auth, filter, email, password).await
}

pub async fn admin_update_user(
    auth: &Auth,
    filter: String,
    email: Option<String>,
    password: Option<String>,
) -> Result<(), AuthError> {
    update_user_by_email(auth, filter, email, password).await
}

pub async fn delete_user(auth: &mut Auth, token: String, filter: String) -> Result<(), AuthError> {
    let (id, _, _, _) = get_user_by_email(auth, filter.clone()).await?;
    // verify that the user is the one deleting their account
    if id != get_id_from_token(auth, token)? {
        return Err(AuthError::InvalidToken);
    }
    // remove all tokens associated with user before deleting user
    for (token, (user_id, _)) in auth.token_list.lock().unwrap().iter() {
        if *user_id == id {
            auth.token_list.lock().unwrap().remove(token);
        }
    }
    delete_user_by_email(auth, filter).await
}

pub async fn admin_delete_user(auth: &Auth, filter: String) -> Result<(), AuthError> {
    let (id, _, _, _) = get_user_by_email(auth, filter.clone()).await?;
    // remove all tokens associated with user before deleting user
    for (token, (user_id, _)) in auth.token_list.lock().unwrap().iter() {
        if *user_id == id {
            auth.token_list.lock().unwrap().remove(token);
        }
    }
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

pub async fn verify_token(auth: &Auth, token: String) -> Result<bool, AuthError> {
    let token_list = auth
        .token_list
        .lock()
        .or(Err(AuthError::UnableToAquireTokenListLock))?;
    match token_list.get(&token) {
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

#[derive(Debug)]
pub enum AuthError {
    // User Errors
    UserAlreadyExists,
    UserDoesNotExist,
    IncorrectUsernameOrPassword,
    // Token Errors
    InvalidToken,
    TokenDoesNotExist,
    UnableToAquireTokenListLock,
    // Database Error
    PostgresError(sqlx::Error),
    RedisError(redis::RedisError),
}

impl AuthError {
    pub fn to_error_message(self) -> &'static str {
        const SERVER_SIDE_ERROR_MESSAGE: &str =
            "An error occured while processing your request. Please try again later.";
        match self {
            AuthError::UserAlreadyExists => "User already exists",
            AuthError::UserDoesNotExist => "User does not exist",
            AuthError::IncorrectUsernameOrPassword => "Incorrect username or password",
            AuthError::InvalidToken => "Invalid token",
            AuthError::TokenDoesNotExist => "Token does not exist",
            AuthError::UnableToAquireTokenListLock => SERVER_SIDE_ERROR_MESSAGE,
            AuthError::PostgresError(_) => SERVER_SIDE_ERROR_MESSAGE,
            AuthError::RedisError(_) => SERVER_SIDE_ERROR_MESSAGE,
        }
    }
}

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
    DatabaseError(sqlx::Error),
}

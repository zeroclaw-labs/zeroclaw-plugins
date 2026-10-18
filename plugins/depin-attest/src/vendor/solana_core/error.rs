use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("{0}")]
    Msg(String),
}

impl CoreError {
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Msg(m.into())
    }
}

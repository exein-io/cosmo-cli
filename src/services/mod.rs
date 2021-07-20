pub mod project_service;
pub mod apikey_service;

use std::{error::Error, fmt::Display};

//TODO
#[derive(Debug)]
pub struct GenericError(pub String);

impl std::fmt::Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0,)
    }
}

impl Error for GenericError {}

#[derive(Debug)]
struct PathError(pub String);

impl Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0,)
    }
}

impl std::error::Error for PathError {}

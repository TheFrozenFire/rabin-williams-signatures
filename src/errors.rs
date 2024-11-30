use thiserror::Error;

#[derive(Error, Debug)]
pub enum RabinWilliamsError {
    #[error("Invalid key size")]
    InvalidKeySize,
    
    #[error("Invalid prime number")]
    InvalidPrime,
    
    #[error("Message too large")]
    MessageTooLarge,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Square root modulo prime computation failed")]
    SquareRootModPrimeFailed,
    
    #[error("Internal computation error")]
    ComputationError,
}

pub type Result<T> = std::result::Result<T, RabinWilliamsError>;

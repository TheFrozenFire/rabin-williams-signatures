use clap::{Parser, Subcommand};
use rabin_williams::{KeyPair, PublicKey, PrivateKey};
use rabin_williams::errors::Result;
use sha2::Sha256;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rabin-williams")]
#[command(about = "Rabin-Williams digital signature CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    Generate {
        /// Bit size for the key (minimum 1024)
        #[arg(short, long, default_value_t = 1024)]
        bits: usize,
        
        /// Output file for the public key (hex-encoded modulus n)
        #[arg(long, default_value = "public_key.hex")]
        public_key: PathBuf,
        
        /// Output file for the private key (hex-encoded p and q, one per line)
        #[arg(long, default_value = "private_key.hex")]
        private_key: PathBuf,
    },
    
    /// Sign a message
    Sign {
        /// Path to the private key file
        #[arg(short = 'k', long)]
        private_key: PathBuf,
        
        /// Message to sign (if not provided, reads from stdin)
        #[arg(short, long)]
        message: Option<String>,
        
        /// Output file for the signature (if not provided, writes to stdout)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    
    /// Verify a signature
    Verify {
        /// Path to the public key file
        #[arg(short = 'k', long)]
        public_key: PathBuf,
        
        /// Path to the signature file
        #[arg(short = 's', long)]
        signature: PathBuf,
        
        /// Message to verify (if not provided, reads from stdin)
        #[arg(short, long)]
        message: Option<String>,
    },
    
    /// Perform blind signing
    BlindSign {
        /// Path to the private key file
        #[arg(short = 'k', long)]
        private_key: PathBuf,
        
        /// Path to the blinded message file (hex-encoded)
        #[arg(short = 'm', long)]
        blinded_message: PathBuf,
        
        /// Output file for the blinded signature (if not provided, writes to stdout)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    
    /// Blind a message for blind signing
    Blind {
        /// Path to the public key file
        #[arg(short = 'k', long)]
        public_key: PathBuf,
        
        /// Message to blind (if not provided, reads from stdin)
        #[arg(short, long)]
        message: Option<String>,
        
        /// Output file for the blinded message (hex-encoded)
        #[arg(short = 'b', long, default_value = "blinded_message.hex")]
        blinded_message: PathBuf,
        
        /// Output file for the blinding factor r (hex-encoded)
        #[arg(short = 'r', long, default_value = "blinding_factor.hex")]
        blinding_factor: PathBuf,
    },
    
    /// Unblind a signature after blind signing
    Unblind {
        /// Path to the public key file
        #[arg(short = 'k', long)]
        public_key: PathBuf,
        
        /// Path to the blinded signature file
        #[arg(short = 's', long)]
        blinded_signature: PathBuf,
        
        /// Path to the blinding factor file (hex-encoded)
        #[arg(short = 'r', long)]
        blinding_factor: PathBuf,
        
        /// Output file for the unblinded signature (if not provided, writes to stdout)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    
    if let Err(e) = match cli.command {
        Commands::Generate { bits, public_key, private_key } => {
            generate_keypair(bits, &public_key, &private_key)
        }
        Commands::Sign { private_key, message, output } => {
            sign_message(&private_key, message.as_deref(), output.as_ref())
        }
        Commands::Verify { public_key, signature, message } => {
            verify_signature(&public_key, &signature, message.as_deref())
        }
        Commands::BlindSign { private_key, blinded_message, output } => {
            blind_sign(&private_key, &blinded_message, output.as_ref())
        }
        Commands::Blind { public_key, message, blinded_message, blinding_factor } => {
            blind_message(&public_key, message.as_deref(), &blinded_message, &blinding_factor)
        }
        Commands::Unblind { public_key, blinded_signature, blinding_factor, output } => {
            unblind_signature(&public_key, &blinded_signature, &blinding_factor, output.as_ref())
        }
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn generate_keypair(bits: usize, public_key_path: &PathBuf, private_key_path: &PathBuf) -> Result<()> {
    println!("Generating {}-bit key pair...", bits);
    let keypair = KeyPair::generate(bits)?;
    
    // Save public key (modulus n)
    let n_hex = hex::encode(keypair.public.n().to_bytes_be());
    fs::write(public_key_path, n_hex)
        .map_err(|_| rabin_williams::RabinWilliamsError::ComputationError)?;
    println!("Public key saved to: {}", public_key_path.display());
    
    // Save private key (p and q, one per line)
    let p_hex = hex::encode(keypair.private.p.to_bytes_be());
    let q_hex = hex::encode(keypair.private.q.to_bytes_be());
    let private_key_content = format!("{}\n{}", p_hex, q_hex);
    fs::write(private_key_path, private_key_content)
        .map_err(|_| rabin_williams::RabinWilliamsError::ComputationError)?;
    println!("Private key saved to: {}", private_key_path.display());
    
    println!("Key pair generated successfully!");
    Ok(())
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKey<Sha256>> {
    let content = fs::read_to_string(path)
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidKeySize)?;
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return Err(rabin_williams::RabinWilliamsError::InvalidKeySize);
    }
    
    let p_bytes: Vec<u8> = hex::decode(lines[0])
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidKeySize)?;
    let q_bytes: Vec<u8> = hex::decode(lines[1])
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidKeySize)?;
    
    let p = num_bigint::BigUint::from_bytes_be(&p_bytes);
    let q = num_bigint::BigUint::from_bytes_be(&q_bytes);
    
    Ok(PrivateKey::from_primes(p, q))
}

fn load_public_key(path: &PathBuf) -> Result<PublicKey<Sha256>> {
    let content = fs::read_to_string(path)
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidKeySize)?;
    let n_bytes: Vec<u8> = hex::decode(content.trim())
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidKeySize)?;
    let n = num_bigint::BigUint::from_bytes_be(&n_bytes);
    
    Ok(PublicKey::from_n(n))
}

fn read_message(message: Option<&str>) -> Result<Vec<u8>> {
    match message {
        Some(m) => Ok(m.as_bytes().to_vec()),
        None => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)
                .map_err(|_| rabin_williams::RabinWilliamsError::MessageTooLarge)?;
            Ok(buffer)
        }
    }
}

fn sign_message(private_key_path: &PathBuf, message: Option<&str>, output: Option<&PathBuf>) -> Result<()> {
    let private_key = load_private_key(private_key_path)?;
    let message_bytes = read_message(message)?;
    
    let signature = private_key.sign(&message_bytes)?;
    let signature_hex = hex::encode(&signature);
    
    match output {
        Some(path) => {
            fs::write(path, signature_hex)
                .map_err(|_| rabin_williams::RabinWilliamsError::ComputationError)?;
            println!("Signature saved to: {}", path.display());
        }
        None => {
            println!("{}", signature_hex);
        }
    }
    
    Ok(())
}

fn verify_signature(public_key_path: &PathBuf, signature_path: &PathBuf, message: Option<&str>) -> Result<()> {
    let public_key = load_public_key(public_key_path)?;
    let message_bytes = read_message(message)?;
    
    let signature_hex = fs::read_to_string(signature_path)
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidSignature)?;
    let signature: Vec<u8> = hex::decode(signature_hex.trim())
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidSignature)?;
    
    let is_valid = public_key.verify(&message_bytes, &signature)?;
    
    if is_valid {
        println!("✓ Signature is valid");
        Ok(())
    } else {
        println!("✗ Signature is invalid");
        Err(rabin_williams::RabinWilliamsError::InvalidSignature)
    }
}

fn blind_sign(private_key_path: &PathBuf, blinded_message_path: &PathBuf, output: Option<&PathBuf>) -> Result<()> {
    let private_key = load_private_key(private_key_path)?;
    
    let blinded_message_hex = fs::read_to_string(blinded_message_path)
        .map_err(|_| rabin_williams::RabinWilliamsError::MessageTooLarge)?;
    let blinded_message_bytes: Vec<u8> = hex::decode(blinded_message_hex.trim())
        .map_err(|_| rabin_williams::RabinWilliamsError::MessageTooLarge)?;
    
    let blinded_signature = private_key.raw_sign(&blinded_message_bytes)?;
    let signature_hex = hex::encode(&blinded_signature);
    
    match output {
        Some(path) => {
            fs::write(path, signature_hex)
                .map_err(|_| rabin_williams::RabinWilliamsError::ComputationError)?;
            println!("Blinded signature saved to: {}", path.display());
        }
        None => {
            println!("{}", signature_hex);
        }
    }
    
    Ok(())
}

fn blind_message(
    public_key_path: &PathBuf,
    message: Option<&str>,
    blinded_message_path: &PathBuf,
    blinding_factor_path: &PathBuf,
) -> Result<()> {
    let public_key = load_public_key(public_key_path)?;
    let message_bytes = read_message(message)?;
    
    let (blinded_message, r) = public_key.blind_message(&message_bytes);
    
    let blinded_message_hex = hex::encode(blinded_message.to_bytes_be());
    fs::write(blinded_message_path, blinded_message_hex)
        .map_err(|_| rabin_williams::RabinWilliamsError::ComputationError)?;
    println!("Blinded message saved to: {}", blinded_message_path.display());
    
    let r_hex = hex::encode(r.to_bytes_be());
    fs::write(blinding_factor_path, r_hex)
        .map_err(|_| rabin_williams::RabinWilliamsError::ComputationError)?;
    println!("Blinding factor saved to: {}", blinding_factor_path.display());
    
    Ok(())
}

fn unblind_signature(
    public_key_path: &PathBuf,
    blinded_signature_path: &PathBuf,
    blinding_factor_path: &PathBuf,
    output: Option<&PathBuf>,
) -> Result<()> {
    let public_key = load_public_key(public_key_path)?;
    
    let blinded_signature_hex = fs::read_to_string(blinded_signature_path)
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidSignature)?;
    let blinded_signature: Vec<u8> = hex::decode(blinded_signature_hex.trim())
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidSignature)?;
    
    let r_hex = fs::read_to_string(blinding_factor_path)
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidSignature)?;
    let r_bytes: Vec<u8> = hex::decode(r_hex.trim())
        .map_err(|_| rabin_williams::RabinWilliamsError::InvalidSignature)?;
    let r = num_bigint::BigUint::from_bytes_be(&r_bytes);
    
    let unblinded_signature = public_key.unblind_signature(&blinded_signature, &r)?;
    let signature_hex = hex::encode(&unblinded_signature);
    
    match output {
        Some(path) => {
            fs::write(path, signature_hex)
                .map_err(|_| rabin_williams::RabinWilliamsError::ComputationError)?;
            println!("Unblinded signature saved to: {}", path.display());
        }
        None => {
            println!("{}", signature_hex);
        }
    }
    
    Ok(())
}


use clap::{Args, Parser, Subcommand};

/// TODO: Useful CLI description here
#[derive(Parser, Debug)]
pub struct CLIArgs {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Encrypt(EncryptCommand),
    Decrypt(DecryptCommand),
    Clear(ClearDirectoryInBucketCommand),
    List(ListFilesInDirectoryInBucketCommand)
}

/// Encrypt a file
#[derive(Args, Debug)]
pub struct EncryptCommand {
    /// The path of the file to split
    #[clap(short, long = "file")]
    pub file_path: String,

    /// The size of each file chunk
    #[clap(short, long)]
    pub chunk_size: usize,

    /// The directory where each chunk (along with the encryption key)
    /// should be saved. The directory will be created if it doesn't
    /// already exist
    #[clap(short, long = "output", value_name = "OUTPUT DIRECTORY")]
    pub output_dir: Option<String>,
}

/// Decrypt a file using a given keystore file
#[derive(Args, Debug)]
pub struct DecryptCommand {
    /// Decrypts a file using the provided keystore.json file
    #[clap(short, long = "key", value_name = "KEYSTORE PATH")]
    pub keystore_path: String,

    /// The name of the decrypted file. If not provided, the filename from the
    /// keystore will be used instead.
    #[clap(short, long = "output", value_name = "OUTPUT FILE",)]
    pub output_file: Option<String>,
}

/// Clear a directory in the bucket.
#[derive(Args, Debug)]
pub struct ClearDirectoryInBucketCommand {
    /// Directory name.
    #[clap(short = 'd', long = "dir", value_name = "DIRECTORY TO CLEAR")]
    pub dir_name: String,
}

/// List all files in a directory in the bucket.
#[derive(Args, Debug)]
pub struct ListFilesInDirectoryInBucketCommand {
    /// Directory name.
    #[clap(short = 'd', long = "dir", value_name = "DIRECTORY TO LIST")]
    pub dir_name: String,
}
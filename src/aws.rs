use s3::creds::Credentials;
use s3::Bucket;
use std::env;

pub async fn write_to_bucket(filename: &str, content: Vec<u8>) {
    let access_key: String = env::var("ACCESS_KEY").expect("Missing variable ACCESS_KEY");
    let secret_key: String = env::var("SECRET_KEY").expect("Missing variable SECRET_KEY");

    let credentials = match Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
    {
        Err(why) => panic!("Invalid creds. Error thrown {}", why),
        Ok(credentials) => credentials,
    };

    let bucket_name = "cop4520-final-project-bucket";
    let region = "us-east-1"
        .parse()
        .expect("Something went wrong parsing region.");
    let bucket = Bucket::new(bucket_name, region, credentials)
        .expect("Something went wrong creating the bucket.");

    // Async variant with `tokio` or `async-std` features
    let (_, _code) = bucket
        .put_object(filename, &content)
        .await
        .expect("Something went wrong putting object in bucket.");
    println!("Code is {}", _code);
}

async fn read_from_bucket(filename: &str) -> Vec<u8> {
    let access_key: String = env::var("ACCESS_KEY").expect("Missing variable ACCESS_KEY");
    let secret_key: String = env::var("SECRET_KEY").expect("Missing variable SECRET_KEY");

    let credentials = match Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
    {
        Err(why) => panic!("Invalid creds. Error thrown {}", why),
        Ok(credentials) => credentials,
    };

    let bucket_name = "cop4520-final-project-bucket";
    let region = "us-east-1"
        .parse()
        .expect("Something went wrong parsing region.");
    let bucket = Bucket::new(bucket_name, region, credentials)
        .expect("Something went wrong creating the bucket.");

    // Async variant with `tokio` or `async-std` features
    let (data, _code) = bucket
        .get_object(filename)
        .await
        .expect("Something went wrong fetching the data. Code {_code}");

    return data;
}
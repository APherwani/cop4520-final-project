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

pub async fn read_from_bucket(filename: &str) -> Vec<u8> {
    let access_key: String = env::var("ACCESS_KEY").expect("Missing variable ACCESS_KEY");
    let secret_key: String = env::var("SECRET_KEY").expect("Missing variable SECRET_KEY");

    let credentials = match Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
    {
        Err(why) => panic!("Invalid credentials. Error thrown {why}"),
        Ok(credentials) => credentials,
    };

    let bucket_name = "cop4520-final-project-bucket";
    let region = "us-east-1"
        .parse()
        .expect("Something went wrong parsing region.");
    let bucket = Bucket::new(bucket_name, region, credentials)
        .expect("Something went wrong initializing the bucket.");

    // Async variant with `tokio` or `async-std` features
    let (data, _code) = bucket
        .get_object(filename)
        .await
        .expect("Something went wrong fetching the data. Code {_code}");

    return data;
}

pub async fn delete_object(path: &str) -> u16 {
    let access_key = env::var("ACCESS_KEY").expect("Missing variable ACCESS_KEY");
    let secret_key = env::var("SECRET_KEY").expect("Missing variable SECRET_KEY");
    
    let credentials = match Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
    {
        Err(why) => panic!("Invalid credentials. Error thrown {why}"),
        Ok(credentials) => credentials,
    };

    let bucket_name = "cop4520-final-project-bucket";
    let region = "us-east-1"
        .parse()
        .expect("Something went wrong parsing the region");
    let bucket = Bucket::new(bucket_name, region, credentials)
        .expect("Something went wrong initializing bucket.");

    // Delete encrypted folder in the bucket.
    let (_, code) = bucket
        .delete_object(path)
        .await
        .expect("Something went wrong deleting the encrypted folder. Code {code}");

    return code;
}

pub async fn list_objects(directory: &str) -> Vec<String> {
    let access_key = env::var("ACCESS_KEY").expect("Missing variable ACCESS_KEY");
    let secret_key = env::var("SECRET_KEY").expect("Missing variable SECRET_KEY");
    
    let credentials = match Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
    {
        Err(why) => panic!("Invalid credentials. Error thrown {why}"),
        Ok(credentials) => credentials,
    };

    let bucket_name = "cop4520-final-project-bucket";
    let region = "us-east-1"
        .parse()
        .expect("Something went wrong parsing the region");
    let bucket = Bucket::new(bucket_name, region, credentials)
        .expect("Something went wrong initializing bucket.");

    let results = bucket.list(directory.to_string(), Some("/".to_string()))
        .await
        .expect("Something failed listing items in the bucket.");

    let mut list = Vec::new();

    for item in &results[0].contents {
        list.push(item.key.clone());
    }
    return list;
}

pub async fn delete_all(directory: &str) {
    let paths = list_objects(directory).await;
    for path in paths {
        delete_object(&path).await;
    }
}
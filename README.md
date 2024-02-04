# AWS ECR SCAN REPORT to CSV

This is my first rust crate based on a simple use case. I need to extract the details of the AWS ECR repositories vulnerabilities scan report, and create a CSV output.
Current version will work with ECR "Basic" and "Enhanced" scan level.

## Getting started

1) Setup AWS account access :

```Shell
$> export AWS_PROFILE=myAwsProfileName
```

2) Scan all account repositories :

```Shell
$> aws-ecr-scan-detail --all
```

Scan a single repository :

```Shell
$> aws-ecr-scan-detail name-of-ecr-repository
```

## How to build
### Install Rust
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
### Build binary
inside of project folder, run:
```
cargo build --release
```
you will find binary at `target/release`


## About

Below are all the steps I went through to create my rust crate. I hope it helps you start your own.

1) Create crate : 

```Shell
$> cargo new aws-ecr-scan-detail
```

2) Add Dependencies :

- Add Tokio

```Shell
$> cargo add tokio --features full
```

- Add AWS Client config

```Shell
$> cargo add aws-config --features behavior-version-latest
```

- Add AWS ECR lib

```Shell
$> cargo add aws-sdk-ecr
```

3) Create main.rs

create a 'src/main.rs' file and add your code

4) Build release

```Shell
$> cargo build --release
```

5) Optimizations

I was looking to reduce the size and footprint of my final binary.

In the __Cargo.toml__, you can add some optimizations for building profile.

```Toml
[profile.release]
overflow-checks = false # Remove overflow checks https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks
incremental = false # Disable creation of incremental info https://doc.rust-lang.org/cargo/reference/profiles.html#incremental
opt-level = 3  # Enable aggressive optimizations for release builds https://doc.rust-lang.org/cargo/reference/profiles.html#opt-level
debug = false  # Strip debug symbols from the binary https://doc.rust-lang.org/cargo/reference/profiles.html#debug
lto = true # Enable better optimizations https://doc.rust-lang.org/cargo/reference/profiles.html#lto
strip = "symbols" # Strip symbols from binary https://doc.rust-lang.org/cargo/reference/profiles.html#strip
```

By adding some arguments to the Rust linker, I was able to reduce consumption.

```Shell
$> export RUSTFLAGS="-C link-args=-lz -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack,-z,nodump,-z,noexecheap,-z,noexpthdrs,-z,defs,-z,nosymtabcompress"
$> cargo build --release
```

## License

aws-ecr-scan-detail is licensed under the Apache 2.0 License. 
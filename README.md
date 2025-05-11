# rustls-async-test

A demonstration of using [rustls](https://github.com/rustls/rustls) with a custom async runtime implementation.

## Project Overview

This project showcases a lightweight, custom async runtime implementation that integrates with the rustls TLS library. Instead of relying on established async runtimes like tokio or async-std, this project demonstrates how to build async primitives from scratch using low-level system primitives like epoll.

### Key Features

- **Custom Async Runtime**: Implements a future executor with epoll-based I/O operations
- **TLS Client**: Uses rustls to establish secure TLS connections
- **Async Primitives**: Includes implementations of common async patterns like:
  - Future polling and waking
  - Async I/O operations (read/write)
  - Timeouts
  - Futures joining and selection
  - Async sleep

## How It Works

The project:

1. Creates a custom async runtime system in the `leo_async` module
2. Implements a TLS client that uses rustls for the TLS protocol
3. Connects to a website over HTTPS
4. Sends a simple HTTP request and displays the response

The example establishes a TLS connection to www.gkbrk.com, retrieves the robots.txt file, and prints the result.

## Getting Started

### Prerequisites

- Rust (edition 2024)
- Cargo

### Running the Example

```bash
cargo run
```

This will execute the `tls_test` function which:
- Connects to www.gkbrk.com over HTTPS (port 443)
- Sends an HTTP request for /robots.txt
- Prints the response

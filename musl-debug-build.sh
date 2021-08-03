# Statically build the executable in debug mode
cargo build --target x86_64-unknown-linux-musl


# i686-musl

# docker pull messense/rust-musl-cross:i686-musl
# alias rust-musl-builder='docker run --rm -it -v "$(pwd)":/home/rust/src  messense/rust-musl-cross:i686-musl'
# rust-musl-builder cargo build --release


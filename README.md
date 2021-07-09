# Exein analyzer CLI


## Usage

```bash
efa [command] [arguments]
```

## How to build
  
Development:  
```bash
cargo build
```

Release:
```bash
cargo build --release
```

## How to package

1. Install makeself
2. Make executable the relese script:
    ```bash
    chmod +x package-release.sh
    ```
3. Launch script:
    ```bash
    ./package-release.sh
    ```


## Features

- [x] List projects
- [x] Get project detail
- [x] Get project overview
- [ ] Delete project
- [x] Create project
- [x] Logout
- [ ] Get analyses
 
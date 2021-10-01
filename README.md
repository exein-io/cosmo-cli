# Exein analyzer CLI


## Getting started
### Usage

```bash
cosmo [command] [arguments]
```

### How to build
  
Development environment:  
```bash
cargo build --no-default-features --features "development"
```

Staging environment:  
```bash
cargo build --no-default-features --features "staging"
```

Release (AWS) environment:
```bash
cargo build --release
```

### How to package

1. Install makeself
2. Make executable the release script:
    ```bash
    chmod +x package-release.sh
    ```
3. Launch the script:
    ```bash
    ./package-release.sh
    ```


## Examples

- List personal projects: `$ cosmo list` or `$ cosmo ls`
- Create a new analysis:  `$ cosmo create -f <fw-path> -t <fw-type> -n <project-name>` or `$ cosmo new -f <fw-path> -t <fw-type> -n <project-name>`
- View project results overview: `$ cosmo overview -i <uuid-project>` or `$ cosmo show -i <uuid-project>`
- View analysis results: `$ cosmo analysis -i <uuid-project> -a PeimDxe`
- Delete project: `$ cosmo delete -i <uuid-project>` or `$ cosmo rm -i <uuid-project>`
- Log out: `$ cosmo logout`
- Create an API key: `$ cosmo apikey -a create`
- List API key: `$ cosmo apikey -a list`
- Delete API key: `$ cosmo apikey -a delete`
- Save PDF report: `$ cosmo report -i <uuid-project>`


## Features

- [x] List projects
- [x] Get project overview
- [x] Delete project
- [x] Create project
- [x] Logout
- [x] Get analyses
- [x] API key
 
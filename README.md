# Exein Cosmo CLI

## Usage

```bash
cosmo [command] [arguments]
```

## How to build
  
```bash
cargo build --release
```

## Examples

- List personal projects: `$ cosmo list` or `$ cosmo ls`
- Create a new analysis:  `$ cosmo create -f <fw-path> -t <fw-type> -n <project-name>` or `$ cosmo new -f <fw-path> -t <fw-type> -n <project-name>`
- View project results overview: `$ cosmo overview -i <uuid-project>` or `$ cosmo show -i <uuid-project>`
- View analysis results: `$ cosmo analysis -i <uuid-project> -a PeimDxe`
- View paginated analysis results: `$ cosmo analysis -i <uuid-project> -a PeimDxe -p 1 -l 10`
- Delete project: `$ cosmo delete -i <uuid-project>` or `$ cosmo rm -i <uuid-project>`
- Log out: `$ cosmo logout`
- Create an API key: `$ cosmo apikey -a create`
- List API key: `$ cosmo apikey -a list`
- Delete API key: `$ cosmo apikey -a delete`
- Save PDF report: `$ cosmo report -i <uuid-project>`
 
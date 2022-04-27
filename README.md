<div align="center">
    <img width="300" src="res/cosmo-logo-exein_color_reverse.png" alt="Cosmo Exein Logo">
 
  <p>
    <a href="https://opensource.org/licenses/Apache-2.0">
      <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
    </a>
  </p>
</div>

<br/>

## Usage

```bash
cosmo [command] [arguments]
```

## Build
  
```bash
cargo build --release
```

## Usage 

| **Description**                 | **Command**                                                                                                                                   |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| List personal projects          | `cosmo list`<br>`cosmo ls`                                                                                                                    |
| Create a new analysis           | `cosmo create -f <firmware-path> -t <firmware-type> -n <project-name>`<br>`cosmo new -f <firmware-path> -t <firmware-type> -n <project-name>` |
| View project results overview   | `cosmo overview -i <project-uuid>` <br>`cosmo show -i <project-uuid>`                                                                         |
| View analysis results           | `cosmo analysis -i <project-uuid> -a PeimDxe`                                                                                                 |
| View paginated analysis results | `cosmo analysis -i <project-uuid> -a PeimDxe -p 1 -l 10`                                                                                      |
| Delete project                  | `cosmo delete -i <project-uuid>`<br>`cosmo rm -i <project-uuid>`                                                                              |
| Log out                         | `cosmo logout`                                                                                                                                |
| Create an API key               | `cosmo apikey -a create`                                                                                                                      |
| List API key                    | `cosmo apikey -a list`                                                                                                                        |
| Save PDF report                 | `cosmo report -i <project-uuid>`                                                                                                              |

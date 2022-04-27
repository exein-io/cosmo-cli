<img width="300" src="res/cosmo-logo-exein_color_reverse.png" alt="Cosmo Exein Logo">

<br/>

The command-line interface tool that allows you to interact with the [Cosmo](https://cosmo.exein.io/) API. 

With the Cosmo CLI tool you are able to manage your projects, run scans, generate reports or manage your API keys to interface directly with the API.

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

## Contributing

To contribute to the project please refer to our [contribution guidelines](./CONTRIBUTING.md).

## License

Copyright (c) Exein SpA. All rights reserved.

Licensed under the [Apache License 2.0 license](./LICENSE).

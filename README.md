# DockerInspect
[![Build Status](https://gitlab.com/shibme/dockerinspect/badges/master/pipeline.svg)](https://gitlab.com/shibme/dockerinspect/pipelines)

Container image scanning made simple for continuous integration

### Before we start,
- Make sure the latest Docker CLI has been installed

#### Some environment variables for DockerInspect 😬
`DOCKERINSPECT_TARGET_IMAGE` - Required
- The image name with tag [Better if available locally. If not, a pull will be attempted]

`DOCKERINSPECT_PROJECT_NAME` - Required
- A unique project name for the scan to avoid duplicate issues

`DOCKERINSPECT_DEPENDENCY_SCAN` - Optional
- Set TRUE if application dependency vulnerabilities also need to be considered

`DOCKERINSPECT_IGNORE_UNFIXED` - Optional
- Set TRUE to ignore unfixed vulnerabilities

`DOCKERINSPECT_TIMEOUT` - Optional
- Sets a timeout for the scan

`DOCKERINSPECT_CLEAR_CACHE` - Optional
- Set TRUE to clear the cache directory
 
#### A few more steps, in case you need to sync the findings to an issue tracker 🙄 [All optional]
- Take a look into [this](https://gitlab.com/shibme/steward/-/blob/master/README.md#configuration-for-consumers) for instructions

### Let's get started 😎
Run the following command on your terminal with the source code in working directory
```
curl -s https://shibme.github.io/dockerinspect/init | sh
```

## Credits
- DockerInspect uses [Trivy](https://github.com/aquasecurity/trivy) as it's underlying tool to scan docker images.
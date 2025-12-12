# Cyber Threat Exchange

[![codecov](https://codecov.io/gh/muchdogesec/cyberthreatexchange/graph/badge.svg?token=R2G4K4aTzM)](https://codecov.io/gh/muchdogesec/cyberthreatexchange)

## Overview

Our ambition is to create a Cyber Threat Exchange that allows;

1. producers to create/submit their intelligence into the exchange
2. consumers to subscribe to a producers feed(s) using a REST / TAXII API.

In order to that, we need a flexible, but structured way for producers to submit their intel and for users to explore it.

This is the core API that will support this.

## Why not just use the stix2 Python library

Our need for something more custom stems from two main requirements:

1. We want to expose this via a web app
2. We want to allows users to use custom objects/properties in a controlled way (via our [stix2extensions](https://github.com/muchdogesec/stix2extensions) repository)
 
## Install

### Download and configure

```shell
# clone the latest code
git clone https://github.com/muchdogesec/cyberthreatexchange
```

### Pre-requisites

**IMPORTANT**: ArangoDB and Postgres must be running. These are not deployed in the compose file.

If you are not sure what you are doing here, [follow the basic setup steps here](https://community.dogesec.com/t/best-way-to-create-databases-for-obstracts/153/2).

### Configuration options

Cyber Threat Exchange has various settings that are defined in an `.env` file.

To create a template for the file:

```shell
cp .env.example .env
```

To see more information about how to set the variables, and what they do, read the `.env.markdown` file.

### Build the Docker Image

```shell
sudo docker compose build
```

### Start the server

```shell
sudo docker compose up
```

### Access the server

The webserver (Django) should now be running on: http://127.0.0.1:8007/

You can access the Swagger UI for the API in a browser at: http://127.0.0.1:8007/api/schema/swagger-ui/

## Support

[Minimal support provided via the dogesec community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).
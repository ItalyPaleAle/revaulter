# Install and configure Revaulter

Revaulter runs as a lightweight app on a server you control that exposes a HTTPS endpoint. You can install it on the same server where the application that requires the cryptographic key runs, or on a separate machine.

> **Firewall rules:** Revaulter must be deployed on a server that admins can connect to via HTTPS, on a port of your choice. While Revaulter doesn't need to be exposed on the public Internet, your admins must be able to connect to it, even if through a private IP or VPN. Additionally, Revaulter must be able to make outgoing HTTPS requests.

## Configuration

Revaulter requires a configuration file `config.yaml` in one of the following paths:

- `/etc/revaulter/config.yaml`
- `$HOME/.revaulter/config.yaml`
- Or in the same folder where the Revaulter binary is located

> You can specify a custom configuration file using the `REVAULTER_CONFIG` environmental variable.

You can find an example of the configuration file, and a description of every option, in the [`config.sample.yaml`](/config.sample.yaml) file.

Keys can also be passed as environmental variables with the `REVAULTER_` prefix.

### Supported configuration options

- Azure credentials:
  - **`azureClientId`** (**required**):  
    Client ID of the Azure AD application (see the [Azure AD application](./01-set-up.md#azure-ad-application) step in the [Set up](./01-set-up.md) document).  
    Environmental variable name: `REVAULTER_AZURECLIENTID`
  - **`azureTenantId`** (**required**):  
    Tenant ID of the Azure AD application.  
    Environmental variable name: `REVAULTER_AZURETENANTID`
- Webhooks:
  - **`webhookUrl`** (**required**):  
    Endpoint of the webhook, where notifications are sent to.  
    Environmental variable name: `REVAULTER_WEBHOOKURL`
  - **`webhookFormat`** (optional, default: `plain`):  
    The format for the webhook. Currently, these values are supported:
    - `plain` (default): sends a webhook with content type `text/plain`, where the request's body is the entire message.
    - `slack`: for usage with Slack or Slack-compatible endpoints
    - `discord`: for usage with Discord (sends Slack-compatible messages)  
    Environmental variable name: `REVAULTER_WEBHOOKFORMAT`
  - **`webhookKey`** (optional):  
    Value for the Authorization header send with the webhook request. Set this if your webhook requires it.  
    Environmental variable name: `REVAULTER_WEBHOOKKEY`
- Revaulter application:
  - **`baseUrl`** (optional but **recommended**, default: `https://localhost:8080`):  
    The URL your application can be reached at. This is used in the links that are sent in webhook notifications.  
    Environmental variable name: `REVAULTER_BASEURL`
  - **`port`** (optional, default: `8080`):  
    Port to bind to.  
    Environmental variable name: `REVAULTER_PORT`
  - **`bind`** (optional, default: `0.0.0.0`):  
    Address/interface to bind to.  
    Environmental variable name: `REVAULTER_BIND`
  - **`tlsPath`**: (optional, defaults to the same folder as the `config.yaml` file):  
    Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem`. Revaulter watches for changes in this folder and automatically reloads the TLS certificates when they're updated.  
    If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.  
    Note that while this value is optional, a TLS certificate is **required** (even if self-signed).  
    Environmental variable name: `REVAULTER_TLSPATH`
  - **`tlsCertPEM`** (optional):  
    Full, PEM-encoded TLS certificate. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.  
    Environmental variable name: `REVAULTER_TLSCERTPEM`
  - **`tlsKeyPEM`** (optional):  
    Full, PEM-encoded TLS key. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.  
    Environmental variable name: `REVAULTER_TLSKEYPEM`
  - **`allowedIps`** (optional):  
    If set, allows connections to the APIs only from the IPs or ranges set here. You can set individual IP addresses (IPv4 or IPv6) or ranges in the CIDR notation, and you can add multiple values separated by commas. For example, to allow connections from localhost and IPs in the `10.x.x.x` range only, set this to: `127.0.0.1,10.0.0.0/8`.  
    Note that this value is used to restrict connections to the `/request` endpoints only. It does not restrict the endpoints used by administrators to confirm (or deny) requests.  
    Environmental variable name: `REVAULTER_ALLOWEDIPS`
  - **`origins`** (optional, default is equal to the value of `baseUrl`):  
    Comma-separated lists of origins that are allowed for CORS. This should be a list of all URLs admins can access Revaulter at. Alternatively, set this to `*` to allow any origin (not recommended).  
    Environmental variable name: `REVAULTER_ORIGINS`
  - **`sessionTimeout`** (optional, default: `5m`)  
    Timeout for sessions before having to authenticate again, as a Go duration. This cannot be more than 1 hour.  
    Environmental variable name: `REVAULTER_SESSIONTIMEOUT`
  - **`requestTimeout`** (optional, default: `5m`):  
    Default timeout for wrap and unwrap requests, as a Go duration. This is the default value, and can be overridden in each request.  
    Environmental variable name: `REVAULTER_REQUESTTIMEOUT`
  - **`enableMetrics`** (optional, default: `false`):
    Enable the metrics server which exposes a Prometheus-compatible endpoint `/metrics`.
    Environmental variable name: `REVAULTER_ENABLEMETRICS`
  - **`metricsPort`** (optional, default: `2112`):  
    Port for the metrics server to bind to.  
    Environmental variable name: `REVAULTER_METRICSPORT`
  - **`metricsBind`** (optional, default: `0.0.0.0`):  
    Address/interface for the metrics server to bind to.  
    Environmental variable name: `REVAULTER_METRICSBIND`
  - **`tokenSigningKey`** (optional, will be randomly generated at startup if empty):  
    String used as key to sign state tokens. If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).  
    Environmental variable name: `REVAULTER_TOKENSIGNINGKEY`
  - **`cookieEncryptionKey`** (optional, will be randomly generated at startup if empty):  
    String used as key to encrypt cookies. If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).  
    Environmental variable name: `REVAULTER_COOKIEENCRYPTIONKEY`
  - **`trustedRequestIdHeader`** (optional):  
    String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.  
    Common values can include:

    - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id ) that's vendor agnostic
    - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)

    If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
    Environmental variable name: `REVAULTER_TRUSTEDREQUESTIDHEADER`
  - **`logLevel`** (optional, default: `info`):  
    Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
    Environmental variable name: `REVAULTER_LOGLEVEL`

## Generating a TLS certificate and key

Using Revaulter requires TLS, for security and performance reasons (to be able to use HTTP/2 for the long-lived requests).

Using a self-signed certificate is an acceptable option if running Revaulter in the same server as your app. You can generate a self-signed TLS certificate using OpenSSL, for example:

```sh
openssl req -x509 -newkey rsa:4096 -keyout tls-key.pem -out tls-cert.pem -days 365 -nodes
```

There are two ways to pass the TLS certificate and key to Revaulter:

1. Write them to files named `tls-cert.pem` and `tls-key.pem` and place them in a folder (for example, `/etc/revaulter`). Then, set `tlsPath` in the configuration to the path where the TLS certificate and key are set. In this case, Revaulter automatically reloads the certificate and key if they change on disk.
2. Directly embed the PEM-encoded certificate and key in the configuration file using the options `tlsCertPEM` and `tlsKeyPEM`.

## Start with Docker

You can run Revaulter as a Docker container. Docker container images are available for Linux and support amd64, arm64, and armv7/armhf.

First, create a folder where you will store the configuration file `config.yaml` and the TLS certificate and key (`tls-cert.pem` and `tls-key.pem`), for example `$HOME/.revaulter`.

You can then start Revaulter with:

```sh
docker run \
  -d \
  -p 8080:8080 \
  -v $HOME/.revaulter:/etc/revaulter \
  ghcr.io/italypaleale/revaulter:1
```

> Revaulter follows semver for versioning. The command above uses the latest version in the 1.x branch. We do not publish a container image tagged "latest".

### Start as standalone app

If you don't want to (or can't) use Docker, you can download the latest version of Revaulter from the [Releases](https://github.com/italypaleale/revaulter/releases) page. Fetch the correct archive for your system and architecture, then extract the files and copy the `revaulter` binary to `/usr/local/bin` or another folder.

Place the configuration for Revaulter in the `/etc/revaulter` folder, including the `config.yaml` file and the TLS certificate and key (`tls-cert.pem` and `tls-key.pem`).

You will need to start Revaulter as a service using the process manager for your system.

For example, for Linux distributions based on **systemd** you can use this unit. Copy this file to `/etc/systemd/system/revaulter.service`:

```conf
[Unit]
Description=Revaulter service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
# Specify the user and group to run Revaulter as
User=daemon
Group=daemon
Restart=always
RestartSec=30
# Path where revaulter is installed
ExecStart=/usr/local/bin/revaulter

[Install]
WantedBy=multi-user.target
```

Start the service and enable it at boot with:

```sh
sudo systemctl enable --now revaulter
```

Using systemd, you can make your own services depend on Revaulter by adding `revaulter.service` as a value for `Wants=` and `After=` in the unit files.

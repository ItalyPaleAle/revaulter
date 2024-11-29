# Set up

Before you can deploy and use Revaulter, you need to perform a few setup steps to create resources on Azure: a Key Vault and an Azure AD application that allows the admin to authenticate and allow or deny operations.

All the steps below must be run on your laptop before you deploy the app. At the end, you'll have the values required for the [`config.yaml`](02-install-and-configure-revaulter.md#configuration) file and for making requests to the service.

You will need an Azure subscription to deploy these services; if you don't have one, you can start a [free trial](https://azure.com/free). All the services we need for Revaulter are either free (Azure AD) or very inexpensive (for most scenarios, you should not spend more than a few cents on Azure Key Vault every month).

## Requirements

You'll need two tools installed in your development machine (these don't need to be installed on your server):

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [jq](https://stedolan.github.io/jq/download/)

Alternatively, you can use [Azure Cloud Shell](https://shell.azure.com) in the browser to run the commands below, which already has all the dependencies available.

## Define the URL

First, define the URL your application is listening on and set it in a shell variable. For example:

```sh
# Using an ip:port notation
APP_URL="https://10.20.30.40:8080"
# Can be a hostname
APP_URL="https://my-revaulter.local:8080"
```

This is the URL an admin will use to reach Revaulter. It doesn't need to be a public address, but it needs to be routable by an admin's laptop (to approve or deny requests).

## Set up Azure resources

### Create a Resource Group on Azure

First, set the location where you want your resources to be created in:

```sh
LOCATION="WestUS2"
```

> You can get the full list of options with: `az account list-locations --output tsv`

Create a Resource Group. Give it a friendly name in the `RG_NAME` variable; this will only be used for displaying in the Azure Portal.

```sh
RG_NAME="Revaulter"
RG_ID=$(az group create \
  --name $RG_NAME \
  --location $LOCATION \
  | jq -r .id)
```

### Create the Azure Key Vault

Create a Key Vault. Set a name in the `KEYVAULT_NAME` variable, which must be globally unique:

```sh
# KEYVAULT_NAME must be globally unique
KEYVAULT_NAME="myrevaulterkv"
az keyvault create \
  --name $KEYVAULT_NAME \
  --enable-rbac-authorization true \
  --resource-group $RG_NAME \
  --location $LOCATION
```

Then assign permissions to the current user to perform operations on keys using Azure RBAC (Role-Based Access Control):

```sh
USER_ACCOUNT=$(az account show | jq -r .user.name)
az role assignment create \
  --assignee "${USER_ACCOUNT}" \
  --role "Key Vault Crypto Officer" \
  --scope "${RG_ID}/providers/Microsoft.KeyVault/vaults/${KEYVAULT_NAME}"
```

Lastly, create a new RSA-4096 key directly inside the vault. You may create multiple keys if needed, each with a different name set in the `KEYVAULT_KEY` variable:

```sh
# Name of the key
KEYVAULT_KEY="wrappingkey1"

# Allowed operations on the key, as a space-separated list.
# The list should include all operations you plan on performing using this key.
# Supported values: encrypt decrypt sign verify wrapKey unwrapKey
KEY_OPS="encrypt decrypt sign verify wrapKey unwrapKey"
az keyvault key create \
  --vault-name $KEYVAULT_NAME \
  --kty RSA \
  --size 4096 \
  --name $KEYVAULT_KEY \
  --ops $KEY_OPS \
  --protection software
```

Take note of the value of `KEYVAULT_KEY`, which will be used when making requests to the Revaulter service.

> Important: the command above generates a new RSA key within the Key Vault and returns the public part of the key.
> Because keys cannot be extracted from Azure Key Vault, you will never see the private key, and there's no way to obtain that (you can, however, create backups that only work inside Azure Key Vault).
>
> If you need access to the private key, consider importing a key inside the Key Vault rather than having it generate a new one for you (e.g. [using the Azure CLI](https://docs.microsoft.com/en-us/cli/azure/keyvault/key?view=azure-cli-latest#az-keyvault-key-import)).

### Azure AD application

Create an app in Azure AD to access Azure Key Vault with a user's delegated permissions.

```sh
# Friendly name for the application
APP_NAME="Revaulter"

# Create the app
APP_ID=$(az ad app create \
  --display-name $APP_NAME \
  --available-to-other-tenants false \
  --oauth2-allow-implicit-flow false \
  | jq -r '.appId')

# Grant permissions for Azure Key Vault
# Note the UUIDs below are constants
az ad app permission add \
  --id $APP_ID \
  --api cfa8b339-82a2-471a-a3c9-0fc0be7a4093 \
  --api-permissions f53da476-18e3-4152-8e01-aec403e6edc0=Scope
```

Take note of the output of the last command, which includes the values for the `config.yaml` file:

- `appId` is the value for **`azureClientId`**
- `tenant` is the value for **`azureTenantId`**

> Note that the Azure AD application does not need permissions on the Key Vault. Instead, Revaulter uses delegated permissions, matching whatever access level the authenticated user has.

Lastly, we need to configure the redirect URIs for the application. There are 3 ways to do that:

#### Option 1: Using Federated Identity Credentials

This is the **recommended** approach when:

- The application is running on Azure on a platform that supports [Managed Identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview). Both system-assigned and user-assigned identities are supported.
- The application is running on platforms that support [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation), for example on Kubernetes (on any cloud or on-premises) or other clouds.

> Check the documentation for your platform on configuring the managed identity or the workload identity for your application.

To use Federated Identity Credentials, first configure the Azure AD application with a redirect URI for a "web" client:

```sh
# Ensure these environmental variables are set from the previous steps
# APP_URL
# APP_ID

# Set the redirect URI for the "web" (confidential) application
az ad app update \
  --id "$APP_ID" \
  --web-redirect-uris "${APP_URL}/auth/confirm"
```

Next, configure the federated credential. The steps below show an example for using managed identity; for using workload identity federation, consult the documentation for your platform.

For managed identity, you will need the **object ID** (i.e. "principal ID") of your identity. This can usually be found on the Azure Portal in the "Identity" section of your resource.

```sh
# Set this to the UUID of your managed identity
IDENTITY_OBJECT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Set the TENANT_ID environmental variable
TENANT_ID=$(az account show | jq -r '.tenantId')

az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters "{\"name\": \"mi-${IDENTITY_OBJECT_ID}\",\"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",\"subject\": \"${IDENTITY_OBJECT_ID}\",\"description\": \"Federated Identity for Managed Identity ${IDENTITY_OBJECT_ID}\",\"audiences\": [\"api://AzureADTokenExchange\"]}"
```

Finally, configure Revaulter by setting a value for **`azureFederatedIdentity`**:

- `"ManagedIdentity"` for using a system-assigned managed identity
- `"ManagedIdentity=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` for using a user-assigned managed identity (replace the placeholder value with the **client ID** of your managed identity)
- `"WorkloadIdentity"` for using workload identity

#### Option 2: Using a web client with a client secret

This option can be used when Revaulter is running anywhere, but it requires storing a client secret that is used by Revaulter to obtain an access token.

> Whenever possible, prefer using Federated Identity Credentials, which do not require shared secrets and do not expire, for better security and reliability.

First, configure the Azure AD application with a redirect URI for a "web" client:

```sh
# Ensure these environmental variables are set from the previous steps
# APP_URL
# APP_ID

# Set the redirect URI for the "web" (confidential) application
az ad app update \
  --id "$APP_ID" \
  --web-redirect-uris "${APP_URL}/auth/confirm"
```

Next, create a new client secret (also called _password_):

```sh
# In this example, the client secret will be valid for 1 year
az ad app credential reset \
  --id "$APP_ID" \
  --append \
  --years 1
```

Take note of the `password` from the output above, which will be the value for the **`azureClientSecret`** property in the configuration for Revaulter.

#### Option 3: Configure a public client (legacy)

In this case, Revaulter is configured as a public client (also called "mobile and desktop app"), and works without a client secret or federated identity.

This option is considered legacy and is **not recommended** for new deployments of Revaulter, as it lacks some additional protections that are possible when Revaulter is configured as a confidential ("web") client. Additionally, Revaulter will show a warning in the logs when it's running as a public client.

In this case, you only need to configure the redirect URI in Revaulter:

```sh
# Ensure these environmental variables are set from the previous steps
# APP_URL
# APP_ID

# Set the redirect URI for the "web" (confidential) application
az ad app update \
  --id "$APP_ID" \
  --public-client-redirect-uris "${APP_URL}/auth/confirm"
```

There are no other steps needed, and no value that needs to be set in the configuration for Revaulter.

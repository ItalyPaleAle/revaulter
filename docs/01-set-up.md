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

# Create the app and set the redirect URIs
APP_ID=$(az ad app create \
  --display-name $APP_NAME \
  --available-to-other-tenants false \
  --oauth2-allow-implicit-flow false \
  | jq -r .appId)
APP_OBJECT_ID=$(az ad app show --id $APP_ID | jq -r .id)
az rest \
  --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/${APP_OBJECT_ID}" \
  --body "{\"publicClient\":{\"redirectUris\":[\"${APP_URL}/auth/confirm\"]}}"

# Grant permissions for Azure Key Vault
az ad app permission add \
  --id $APP_ID \
  --api cfa8b339-82a2-471a-a3c9-0fc0be7a4093 \
  --api-permissions f53da476-18e3-4152-8e01-aec403e6edc0=Scope
```

Take note of the output of the last command, which includes the values for the `config.yaml` file:

- `appId` is the value for `azureClientId`
- `tenant` is the value for `azureTenantId`

> Note that the Azure AD application does not need permissions on the Key Vault. Instead, Revaulter uses delegated permissions, matching whatever access level the authenticated user has.

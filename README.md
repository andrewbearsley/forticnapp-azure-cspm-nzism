# FortiCNAPP NZISM v3.7 Compliance Framework

FortiCNAPP compliance framework mapping the New Zealand Information Security Manual (NZISM) Restricted v3.7 to Azure CSPM policies.

Adopts Microsoft and GCSB NCSC's NZISM v3.7 control selection and binds it to FortiCNAPP's `lacework-global-*` Azure policy library.

## Files

- `nzism_v3_7.json`: the framework definition

## Apply to a tenant

The Framework Catalog is backed by `/api/v2/Frameworks`. The Lacework CLI does not wrap this endpoint yet, so use the API directly.

```bash
# Bearer token swap
API_KEY=<key id>
API_SECRET=<secret>
ACCOUNT=<account subdomain>

TOKEN=$(curl -s -X POST "https://${ACCOUNT}.lacework.net/api/v2/access/tokens" \
  -H "Content-Type: application/json" \
  -H "X-LW-UAKS: $API_SECRET" \
  -d "{\"keyId\":\"$API_KEY\",\"expiryTime\":3600}" | jq -r '.token')

# Create
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://${ACCOUNT}.lacework.net/api/v2/Frameworks" \
  -d @nzism_v3_7.json | jq '.data | {guid, name, domains, sectionCount: (.sections | length)}'

# List
curl -s -H "Authorization: Bearer $TOKEN" "https://${ACCOUNT}.lacework.net/api/v2/Frameworks" \
  | jq '.data[] | select(.name | test("NZISM"; "i"))'
```

In the FortiCNAPP console: Compliance > Framework Catalog > Managed by you. Filter Provider to Azure.

## Schema

```json
{
  "name": "...",
  "domains": ["AZURE"],
  "tags": [],
  "sections": [
    {
      "name": "...",
      "policies": [
        { "policyId": "lacework-global-..." }
      ]
    }
  ]
}
```

- `domains` valid values include `AWS`, `AZURE`, `GCP`
- Each `policyId` must already exist in the target tenant. Cross-CSP ids (an AWS `lacework-global-*` in an Azure framework) are accepted but produce no findings.
- POST creates a new framework (HTTP 201). The API does not support in-place updates for user-owned frameworks. To revise, click Delete in the Framework Catalog UI and re-POST.

## Enabling the underlying policies

A subset of Lacework's Azure policy library ships disabled by default in any given tenant. Once the framework is applied, find the disabled policies in this set:

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://${ACCOUNT}.lacework.net/api/v2/Policies" \
  | jq -r --slurpfile fw nzism_v3_7.json '
      ([$fw[0].sections[].policies[].policyId] | unique) as $ids
      | .data[] | select((.policyId | IN($ids[])) and .enabled == false and .policyType == "Compliance")
      | "\(.policyId)\t\(.severity)\t\(.title)"'
```

Enable each one:

```bash
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://${ACCOUNT}.lacework.net/api/v2/Policies/<policyId>" \
  -d '{"enabled": true}'
```

Policies of `policyType: Manual` produce no automated findings and are intentionally retained in the framework for auditor walk-through.

## Coverage

### Chapter 2: Information Security Services within Government

- `lacework-global-1040` — Ensure a Managed Identity is used for interactions with other Azure services
- `lacework-global-1041` — Assign roles to a Managed Identity using the principle of least privilege
- `lacework-global-1047` — Implement and review access policies periodically
- `lacework-global-1048` — Set 'System Assigned Managed Identity' to 'On'
- `lacework-global-1050` — Use Entra ID client authentication and apply Azure RBAC whenever possible
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1395` — Enable Confidential Computing on Virtual Machines (VMs)
- `lacework-global-1880` — Ensure Azure Arc-enabled Kubernetes clusters have Azure RBAC enabled for cluster access
- `lacework-global-525` — Ensure That 'All users with the following roles' is set to 'Owner'
- `lacework-global-526` — Ensure 'Additional email addresses' is Configured with a Security Contact Email
- `lacework-global-527` — Ensure that 'Notify about alerts with the following severity (or higher)' is enabled
- `lacework-global-553` — Enable Azure Monitor Resource Logging for All Services that Support it
- `lacework-global-582` — Enable Register with Azure Active Directory on App Service
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-639` — Ensure that Role Based Access Control for Azure Key Vault is enabled
- `lacework-global-642` — Set up App Service Authentication for apps in Azure App Service

### Chapter 3: Information security governance - roles and responsibilities

- `lacework-global-1023` — Ensure that 'Notify about attack paths with the following severity (or higher)' is enabled
- `lacework-global-1025` — Set the 'Agentless scanning for machines' component status to 'On'
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1104` — Encrypt traffic between cluster worker nodes
- `lacework-global-1403` — Enable Automatic OS Upgrades on Virtual Machines (VMs)
- `lacework-global-1959` — Ensure Azure Arc-enabled machines have automatic agent upgrades enabled
- `lacework-global-1960` — Ensure Azure Arc-enabled Windows machines have periodic update assessment enabled
- `lacework-global-1980` — Ensure Azure Arc machine extensions have automatic upgrades enabled
- `lacework-global-405` — Set Microsoft Defender External Attack Surface Monitoring (EASM) to enabled
- `lacework-global-415` — Set an Expiration Time for all Keys in Role Based Access Control (RBAC) Key Vaults
- `lacework-global-416` — Set an Expiration Date for all Keys in Non Role Based Access Control (RBAC) Key Vaults
- `lacework-global-417` — Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults
- `lacework-global-522` — Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates
- `lacework-global-523` — Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'
- `lacework-global-525` — Ensure That 'All users with the following roles' is set to 'Owner'
- `lacework-global-526` — Ensure 'Additional email addresses' is Configured with a Security Contact Email
- `lacework-global-527` — Ensure that 'Notify about alerts with the following severity (or higher)' is enabled
- `lacework-global-529` — Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
- `lacework-global-530` — Ensure that Storage Account Access Keys are Periodically Regenerated
- `lacework-global-578` — Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-600` — Ensure that 'File Integrity Monitoring' component status is set to 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-611` — Ensure that 'Vulnerability assessment for machines' component status is set to 'On'
- `lacework-global-614` — Ensure that 'Endpoint protection' component status is set to 'On'
- `lacework-global-637` — Ensure that Endpoint Protection for all Virtual Machines is installed
- `lacework-global-641` — Ensure automatic key rotation is enabled within Azure Key Vault

### Chapter 5: Information security documentation

- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1062` — Enable soft delete on backup vaults
- `lacework-global-1063` — Enable immutability on backup vaults
- `lacework-global-1066` — Enable Cross Region Restore on backup vaults
- `lacework-global-1068` — Enable soft delete on Recovery Services vaults
- `lacework-global-1069` — Enable immutability for Recovery Services vaults
- `lacework-global-1073` — Enable Cross Region Restore on Recovery Services vaults
- `lacework-global-1096` — Set Redundancy to geo-redundant storage (GRS) on critical Azure Storage Accounts
- `lacework-global-1104` — Encrypt traffic between cluster worker nodes
- `lacework-global-2025` — Ensure Cosmos DB accounts have continuous backup enabled
- `lacework-global-525` — Ensure That 'All users with the following roles' is set to 'Owner'
- `lacework-global-526` — Ensure 'Additional email addresses' is Configured with a Security Contact Email
- `lacework-global-527` — Ensure that 'Notify about alerts with the following severity (or higher)' is enabled
- `lacework-global-579` — Ensure the Key Vault is Recoverable
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible

### Chapter 6: Information security monitoring

- `lacework-global-1018` — Configure a Microsoft Entra diagnostic setting to send Microsoft Entra activity logs to an appropriate destination
- `lacework-global-1023` — Ensure that 'Notify about attack paths with the following severity (or higher)' is enabled
- `lacework-global-1025` — Set the 'Agentless scanning for machines' component status to 'On'
- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1062` — Enable soft delete on backup vaults
- `lacework-global-1063` — Enable immutability on backup vaults
- `lacework-global-1066` — Enable Cross Region Restore on backup vaults
- `lacework-global-1096` — Set Redundancy to geo-redundant storage (GRS) on critical Azure Storage Accounts
- `lacework-global-1112` — Ensure Azure Arc-enabled SQL Server instances have automated backup policies configured
- `lacework-global-1430` — Ensure That Microsoft Defender for ARC enabled SQL instance is on
- `lacework-global-1581` — Ensure Azure Maintenance Configurations for Guest Patching Have Reboot Settings Configured
- `lacework-global-1582` — Ensure Azure Maintenance Configurations for InGuestPatch Include Security Update Classifications
- `lacework-global-1881` — Ensure Azure Arc-enabled Kubernetes clusters have automatic agent upgrades enabled
- `lacework-global-1899` — Ensure Azure Kubernetes Extensions Have Auto-Upgrade for Minor Versions Enabled
- `lacework-global-1960` — Ensure Azure Arc-enabled Windows machines have periodic update assessment enabled
- `lacework-global-405` — Set Microsoft Defender External Attack Surface Monitoring (EASM) to enabled
- `lacework-global-415` — Set an Expiration Time for all Keys in Role Based Access Control (RBAC) Key Vaults
- `lacework-global-416` — Set an Expiration Date for all Keys in Non Role Based Access Control (RBAC) Key Vaults
- `lacework-global-417` — Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults
- `lacework-global-522` — Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates
- `lacework-global-529` — Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
- `lacework-global-553` — Enable Azure Monitor Resource Logging for All Services that Support it
- `lacework-global-554` — Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs
- `lacework-global-578` — Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults
- `lacework-global-579` — Ensure the Key Vault is Recoverable
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-599` — Ensure That Microsoft Defender for App Services Is Set To 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-602` — Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'
- `lacework-global-603` — Set Microsoft Defender for Open-Source Relational Databases To 'On'
- `lacework-global-604` — Ensure That Microsoft Defender for Storage Is Set To 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-607` — Ensure That Microsoft Defender for Key Vault Is Set To 'On'
- `lacework-global-610` — Ensure That Microsoft Defender for Resource Manager Is Set To 'On'
- `lacework-global-611` — Ensure that 'Vulnerability assessment for machines' component status is set to 'On'
- `lacework-global-612` — Set 'Agentless container vulnerability assessment' component status to 'On'
- `lacework-global-614` — Ensure that 'Endpoint protection' component status is set to 'On'
- `lacework-global-622` — Set Microsoft Defender for SQL to 'On' for critical SQL Servers
- `lacework-global-623` — Enable Vulnerability Assessment (VA) on a SQL server by setting a Storage Account
- `lacework-global-624` — Set Vulnerability Assessment (VA) setting 'Periodic recurring scans' to 'on' for each SQL server
- `lacework-global-625` — Configure Vulnerability Assessment (VA) setting 'Send scan reports to' for a SQL server
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible
- `lacework-global-637` — Ensure that Endpoint Protection for all Virtual Machines is installed
- `lacework-global-641` — Ensure automatic key rotation is enabled within Azure Key Vault

### Chapter 7: Information Security Incidents

- `lacework-global-1023` — Ensure that 'Notify about attack paths with the following severity (or higher)' is enabled
- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1066` — Enable Cross Region Restore on backup vaults
- `lacework-global-1068` — Enable soft delete on Recovery Services vaults
- `lacework-global-1069` — Enable immutability for Recovery Services vaults
- `lacework-global-1070` — Encrypt backup data in Recovery Services vaults using CMK
- `lacework-global-1071` — Enable 'Use infrastructure encryption for this vault' on Recovery Services vaults
- `lacework-global-1073` — Enable Cross Region Restore on Recovery Services vaults
- `lacework-global-1112` — Ensure Azure Arc-enabled SQL Server instances have automated backup policies configured
- `lacework-global-1573` — Azure SQL virtual machines should have auto backup encryption enabled
- `lacework-global-525` — Ensure That 'All users with the following roles' is set to 'Owner'
- `lacework-global-526` — Ensure 'Additional email addresses' is Configured with a Security Contact Email
- `lacework-global-527` — Ensure that 'Notify about alerts with the following severity (or higher)' is enabled
- `lacework-global-579` — Ensure the Key Vault is Recoverable
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible

### Chapter 9: Personnel Security

- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1104` — Encrypt traffic between cluster worker nodes
- `lacework-global-1403` — Enable Automatic OS Upgrades on Virtual Machines (VMs)
- `lacework-global-1581` — Ensure Azure Maintenance Configurations for Guest Patching Have Reboot Settings Configured
- `lacework-global-1582` — Ensure Azure Maintenance Configurations for InGuestPatch Include Security Update Classifications
- `lacework-global-1880` — Ensure Azure Arc-enabled Kubernetes clusters have Azure RBAC enabled for cluster access
- `lacework-global-1959` — Ensure Azure Arc-enabled machines have automatic agent upgrades enabled
- `lacework-global-1960` — Ensure Azure Arc-enabled Windows machines have periodic update assessment enabled
- `lacework-global-1980` — Ensure Azure Arc machine extensions have automatic upgrades enabled
- `lacework-global-522` — Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-600` — Ensure that 'File Integrity Monitoring' component status is set to 'On'
- `lacework-global-611` — Ensure that 'Vulnerability assessment for machines' component status is set to 'On'
- `lacework-global-614` — Ensure that 'Endpoint protection' component status is set to 'On'
- `lacework-global-637` — Ensure that Endpoint Protection for all Virtual Machines is installed

### Chapter 10: Infrastructure

- `lacework-global-1050` — Use Entra ID client authentication and apply Azure RBAC whenever possible
- `lacework-global-1509` — Azure Event Hub namespaces do not use customer-managed keys for encryption
- `lacework-global-1510` — Azure Event Hub namespaces have public network access enabled
- `lacework-global-1511` — Azure Event Hub namespaces do not have infrastructure encryption enabled
- `lacework-global-1523` — Ensure Azure Service Bus namespaces have local authentication disabled

### Chapter 11: Communications Systems and Devices

- `lacework-global-1509` — Azure Event Hub namespaces do not use customer-managed keys for encryption
- `lacework-global-1510` — Azure Event Hub namespaces have public network access enabled
- `lacework-global-1511` — Azure Event Hub namespaces do not have infrastructure encryption enabled

### Chapter 12: Product Security

- `lacework-global-1025` — Set the 'Agentless scanning for machines' component status to 'On'
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1395` — Enable Confidential Computing on Virtual Machines (VMs)
- `lacework-global-1468` — Azure Container Registries must enable Soft Delete protection
- `lacework-global-1797` — Ensure Azure Service Fabric clusters use automatic upgrade mode for security patches
- `lacework-global-1881` — Ensure Azure Arc-enabled Kubernetes clusters have automatic agent upgrades enabled
- `lacework-global-1899` — Ensure Azure Kubernetes Extensions Have Auto-Upgrade for Minor Versions Enabled
- `lacework-global-1959` — Ensure Azure Arc-enabled machines have automatic agent upgrades enabled
- `lacework-global-1960` — Ensure Azure Arc-enabled Windows machines have periodic update assessment enabled
- `lacework-global-522` — Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates
- `lacework-global-524` — Set Auto provisioning of 'Log Analytics agent for Azure VMs' to 'On'
- `lacework-global-542` — Set Vulnerability Assessment (VA) setting 'Also send email notifications to admins and subscription owners' for each SQL Server
- `lacework-global-560` — Ensure that Activity Log Alert exists for Create or Update Network Security Group
- `lacework-global-568` — Ensure that RDP access from the Internet is evaluated and restricted
- `lacework-global-569` — Ensure that SSH access from the Internet is evaluated and restricted
- `lacework-global-570` — Ensure that UDP access from the Internet is evaluated and restricted
- `lacework-global-571` — Ensure that HTTP(S) access from the Internet is evaluated and restricted
- `lacework-global-574` — Install Only Approved Extensions
- `lacework-global-579` — Ensure the Key Vault is Recoverable
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-602` — Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'
- `lacework-global-603` — Set Microsoft Defender for Open-Source Relational Databases To 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-611` — Ensure that 'Vulnerability assessment for machines' component status is set to 'On'
- `lacework-global-612` — Set 'Agentless container vulnerability assessment' component status to 'On'
- `lacework-global-614` — Ensure that 'Endpoint protection' component status is set to 'On'
- `lacework-global-622` — Set Microsoft Defender for SQL to 'On' for critical SQL Servers
- `lacework-global-623` — Enable Vulnerability Assessment (VA) on a SQL server by setting a Storage Account
- `lacework-global-624` — Set Vulnerability Assessment (VA) setting 'Periodic recurring scans' to 'on' for each SQL server
- `lacework-global-625` — Configure Vulnerability Assessment (VA) setting 'Send scan reports to' for a SQL server
- `lacework-global-637` — Ensure that Endpoint Protection for all Virtual Machines is installed

### Chapter 13: Media and IT Equipment Management

- `lacework-global-579` — Ensure the Key Vault is Recoverable

### Chapter 14: Software security

- `lacework-global-1016` — Capture virtual network flow logs and send them to Log Analytics
- `lacework-global-1023` — Ensure that 'Notify about attack paths with the following severity (or higher)' is enabled
- `lacework-global-1025` — Set the 'Agentless scanning for machines' component status to 'On'
- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1038` — Ensure Private Virtual Networks are used for Container Instances
- `lacework-global-1040` — Ensure a Managed Identity is used for interactions with other Azure services
- `lacework-global-1048` — Set 'System Assigned Managed Identity' to 'On'
- `lacework-global-1049` — Disable Public Network Access for REDIS cache
- `lacework-global-1056` — Encrypt critical data using customer-managed keys
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1072` — Disable Public Network Access on Recovery Services vaults
- `lacework-global-1099` — Storage Accounts should have shared key access disabled
- `lacework-global-1132` — Ensure Operations Management Solutions are associated with a valid Log Analytics workspace
- `lacework-global-1277` — Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'
- `lacework-global-1409` — Azure Monitor Logs for Application Insights should be linked to a Log Analytics workspace
- `lacework-global-1467` — Azure Container Registries must disable public network access
- `lacework-global-1510` — Azure Event Hub namespaces have public network access enabled
- `lacework-global-1523` — Ensure Azure Service Bus namespaces have local authentication disabled
- `lacework-global-1530` — Ensure Azure Cache for Redis has public network access disabled
- `lacework-global-1533` — Azure Front Door instances do not have WAF enabled
- `lacework-global-1543` — Ensure Azure API Management services have managed identities enabled
- `lacework-global-1544` — Ensure Azure API Management services have public network access disabled when using private endpoints
- `lacework-global-1565` — Azure Container Instances should not have public IP addresses
- `lacework-global-1575` — Azure App Configuration stores with private endpoints should disable public network access
- `lacework-global-1585` — Azure Stream Analytics jobs do not have diagnostic settings configured
- `lacework-global-1607` — Ensure Azure Batch accounts have public network access disabled
- `lacework-global-1755` — Ensure Azure Batch accounts have network profile configured with account access default action set to Deny
- `lacework-global-1776` — Ensure Azure Maps accounts do not allow unrestricted CORS origins
- `lacework-global-1935` — Ensure Azure Spring Apps is deployed in a virtual network
- `lacework-global-1953` — Ensure that 'Public Network Access' is 'Disabled' for storage accounts
- `lacework-global-2022` — Ensure Cosmos DB accounts have local authentication disabled
- `lacework-global-2026` — Ensure Cosmos DB accounts restrict network ACL bypass
- `lacework-global-405` — Set Microsoft Defender External Attack Surface Monitoring (EASM) to enabled
- `lacework-global-415` — Set an Expiration Time for all Keys in Role Based Access Control (RBAC) Key Vaults
- `lacework-global-416` — Set an Expiration Date for all Keys in Non Role Based Access Control (RBAC) Key Vaults
- `lacework-global-522` — Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates
- `lacework-global-526` — Ensure 'Additional email addresses' is Configured with a Security Contact Email
- `lacework-global-527` — Ensure that 'Notify about alerts with the following severity (or higher)' is enabled
- `lacework-global-532` — Ensure that 'allowBlobPublicAccess' is 'Disabled' for storage accounts
- `lacework-global-533` — Ensure Default Network Access Rule for Storage Accounts is Set to Deny
- `lacework-global-534` — Ensure Private Endpoints are used to access Storage Accounts
- `lacework-global-537` — Set 'Auditing' to 'On'
- `lacework-global-538` — Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (any IP)
- `lacework-global-539` — Ensure that Microsoft Entra authentication is Configured for SQL Servers
- `lacework-global-541` — Ensure that 'Auditing' Retention is 'greater than 90 days'
- `lacework-global-549` — Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled
- `lacework-global-553` — Enable Azure Monitor Resource Logging for All Services that Support it
- `lacework-global-554` — Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs
- `lacework-global-555` — Ensure Diagnostic Setting captures appropriate categories
- `lacework-global-557` — Ensure that logging for Azure Key Vault is 'Enabled'
- `lacework-global-568` — Ensure that RDP access from the Internet is evaluated and restricted
- `lacework-global-569` — Ensure that SSH access from the Internet is evaluated and restricted
- `lacework-global-570` — Ensure that UDP access from the Internet is evaluated and restricted
- `lacework-global-571` — Ensure that HTTP(S) access from the Internet is evaluated and restricted
- `lacework-global-573` — Ensure Virtual Machines are utilizing Managed Disks
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-599` — Ensure That Microsoft Defender for App Services Is Set To 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-602` — Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'
- `lacework-global-603` — Set Microsoft Defender for Open-Source Relational Databases To 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-607` — Ensure That Microsoft Defender for Key Vault Is Set To 'On'
- `lacework-global-610` — Ensure That Microsoft Defender for Resource Manager Is Set To 'On'
- `lacework-global-611` — Ensure that 'Vulnerability assessment for machines' component status is set to 'On'
- `lacework-global-612` — Set 'Agentless container vulnerability assessment' component status to 'On'
- `lacework-global-614` — Ensure that 'Endpoint protection' component status is set to 'On'
- `lacework-global-615` — Ensure that 'Enable Infrastructure Encryption' for Each Storage Account in Azure Storage is Set to 'enabled'
- `lacework-global-617` — Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access
- `lacework-global-622` — Set Microsoft Defender for SQL to 'On' for critical SQL Servers
- `lacework-global-623` — Enable Vulnerability Assessment (VA) on a SQL server by setting a Storage Account
- `lacework-global-624` — Set Vulnerability Assessment (VA) setting 'Periodic recurring scans' to 'on' for each SQL server
- `lacework-global-625` — Configure Vulnerability Assessment (VA) setting 'Send scan reports to' for a SQL server
- `lacework-global-628` — Limit 'Firewalls & Networks' to Use Selected Networks Instead of All Networks
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible
- `lacework-global-631` — Capture Network Security Group (NSG) Flow logs and send to Log Analytics
- `lacework-global-637` — Ensure that Endpoint Protection for all Virtual Machines is installed
- `lacework-global-640` — Ensure that Private Endpoints are Used for Azure Key Vault
- `lacework-global-642` — Set up App Service Authentication for apps in Azure App Service
- `lacework-global-947` — Ensure Azure SignalR Service instances disable public network access

### Chapter 16: Access Control and Passwords

- `lacework-global-1011` — Avoid using Azure admin accounts for daily operations
- `lacework-global-1016` — Capture virtual network flow logs and send them to Log Analytics
- `lacework-global-1022` — Set virtual network flow log retention to 90 days or more
- `lacework-global-1023` — Ensure that 'Notify about attack paths with the following severity (or higher)' is enabled
- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1032` — Enable 'Default to Microsoft Entra authorization in the Azure portal'
- `lacework-global-1040` — Ensure a Managed Identity is used for interactions with other Azure services
- `lacework-global-1045` — Only allow SSL access for Azure redis cache
- `lacework-global-1046` — Set the 'Minimum TLS version' to TLS v1.2 or higher
- `lacework-global-1048` — Set 'System Assigned Managed Identity' to 'On'
- `lacework-global-1049` — Disable Public Network Access for REDIS cache
- `lacework-global-1050` — Use Entra ID client authentication and apply Azure RBAC whenever possible
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1072` — Disable Public Network Access on Recovery Services vaults
- `lacework-global-1099` — Storage Accounts should have shared key access disabled
- `lacework-global-1132` — Ensure Operations Management Solutions are associated with a valid Log Analytics workspace
- `lacework-global-1139` — Ensure Operations Management Solutions have successfully completed provisioning
- `lacework-global-1277` — Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'
- `lacework-global-1385` — Azure Key Vault resources are not configured with diagnostic settings
- `lacework-global-1394` — Azure virtual machines are not configured with complete Microsoft Entra ID authentication
- `lacework-global-1395` — Enable Confidential Computing on Virtual Machines (VMs)
- `lacework-global-1403` — Enable Automatic OS Upgrades on Virtual Machines (VMs)
- `lacework-global-1409` — Azure Monitor Logs for Application Insights should be linked to a Log Analytics workspace
- `lacework-global-1433` — Azure Network Security Group Diagnostic Settings Not Configured for Security Monitoring
- `lacework-global-1452` — Azure Log Analytics Workspaces Use Private Link Configuration
- `lacework-global-1453` — Ensure Azure Log Analytics Workspaces Have Adequate Data Retention Policies
- `lacework-global-1480` — Ensure Azure Logic Apps workflows have diagnostic settings enabled
- `lacework-global-1510` — Azure Event Hub namespaces have public network access enabled
- `lacework-global-1523` — Ensure Azure Service Bus namespaces have local authentication disabled
- `lacework-global-1530` — Ensure Azure Cache for Redis has public network access disabled
- `lacework-global-1531` — Ensure Azure Cache for Redis enforces minimum TLS version 1.2 or higher
- `lacework-global-1532` — Ensure Azure Cache for Redis has non-SSL port access disabled
- `lacework-global-1533` — Azure Front Door instances do not have WAF enabled
- `lacework-global-1543` — Ensure Azure API Management services have managed identities enabled
- `lacework-global-1544` — Ensure Azure API Management services have public network access disabled when using private endpoints
- `lacework-global-1571` — Ensure Azure App Configuration stores have local authentication disabled
- `lacework-global-1575` — Azure App Configuration stores with private endpoints should disable public network access
- `lacework-global-1585` — Azure Stream Analytics jobs do not have diagnostic settings configured
- `lacework-global-1607` — Ensure Azure Batch accounts have public network access disabled
- `lacework-global-1642` — Ensure Azure App Service Certificate Orders are not expired
- `lacework-global-1653` — Ensure Azure IoT Hub has diagnostic settings enabled for security monitoring
- `lacework-global-1755` — Ensure Azure Batch accounts have network profile configured with account access default action set to Deny
- `lacework-global-1776` — Ensure Azure Maps accounts do not allow unrestricted CORS origins
- `lacework-global-1953` — Ensure that 'Public Network Access' is 'Disabled' for storage accounts
- `lacework-global-1960` — Ensure Azure Arc-enabled Windows machines have periodic update assessment enabled
- `lacework-global-2022` — Ensure Cosmos DB accounts have local authentication disabled
- `lacework-global-2026` — Ensure Cosmos DB accounts restrict network ACL bypass
- `lacework-global-398` — Ensure an Azure Bastion Host Exists
- `lacework-global-405` — Set Microsoft Defender External Attack Surface Monitoring (EASM) to enabled
- `lacework-global-412` — Configure Application Insights for Web Apps
- `lacework-global-415` — Set an Expiration Time for all Keys in Role Based Access Control (RBAC) Key Vaults
- `lacework-global-416` — Set an Expiration Date for all Keys in Non Role Based Access Control (RBAC) Key Vaults
- `lacework-global-417` — Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults
- `lacework-global-502` — Set a Custom Bad Password List to 'Enforce' for your Organization
- `lacework-global-522` — Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates
- `lacework-global-523` — Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'
- `lacework-global-525` — Ensure That 'All users with the following roles' is set to 'Owner'
- `lacework-global-526` — Ensure 'Additional email addresses' is Configured with a Security Contact Email
- `lacework-global-527` — Ensure that 'Notify about alerts with the following severity (or higher)' is enabled
- `lacework-global-529` — Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
- `lacework-global-532` — Ensure that 'allowBlobPublicAccess' is 'Disabled' for storage accounts
- `lacework-global-533` — Ensure Default Network Access Rule for Storage Accounts is Set to Deny
- `lacework-global-534` — Ensure Private Endpoints are used to access Storage Accounts
- `lacework-global-537` — Set 'Auditing' to 'On'
- `lacework-global-539` — Ensure that Microsoft Entra authentication is Configured for SQL Servers
- `lacework-global-541` — Ensure that 'Auditing' Retention is 'greater than 90 days'
- `lacework-global-549` — Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled
- `lacework-global-553` — Enable Azure Monitor Resource Logging for All Services that Support it
- `lacework-global-554` — Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs
- `lacework-global-555` — Ensure Diagnostic Setting captures appropriate categories
- `lacework-global-557` — Ensure that logging for Azure Key Vault is 'Enabled'
- `lacework-global-568` — Ensure that RDP access from the Internet is evaluated and restricted
- `lacework-global-569` — Ensure that SSH access from the Internet is evaluated and restricted
- `lacework-global-578` — Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults
- `lacework-global-582` — Enable Register with Azure Active Directory on App Service
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-599` — Ensure That Microsoft Defender for App Services Is Set To 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-604` — Ensure That Microsoft Defender for Storage Is Set To 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-607` — Ensure That Microsoft Defender for Key Vault Is Set To 'On'
- `lacework-global-609` — Ensure That Microsoft Defender for IoT Hub Is Set To 'On'
- `lacework-global-610` — Ensure That Microsoft Defender for Resource Manager Is Set To 'On'
- `lacework-global-617` — Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access
- `lacework-global-628` — Limit 'Firewalls & Networks' to Use Selected Networks Instead of All Networks
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible
- `lacework-global-631` — Capture Network Security Group (NSG) Flow logs and send to Log Analytics
- `lacework-global-632` — Enable logging for Azure AppService 'HTTP logs'
- `lacework-global-633` — Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'
- `lacework-global-639` — Ensure that Role Based Access Control for Azure Key Vault is enabled
- `lacework-global-641` — Ensure automatic key rotation is enabled within Azure Key Vault
- `lacework-global-642` — Set up App Service Authentication for apps in Azure App Service
- `lacework-global-947` — Ensure Azure SignalR Service instances disable public network access
- `lacework-global-994` — Configure network security groups for Databricks subnets

### Chapter 17: Cryptography

- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1031` — Use Azure Key Vault Managed HSM when required
- `lacework-global-1038` — Ensure Private Virtual Networks are used for Container Instances
- `lacework-global-1046` — Set the 'Minimum TLS version' to TLS v1.2 or higher
- `lacework-global-1049` — Disable Public Network Access for REDIS cache
- `lacework-global-1056` — Encrypt critical data using customer-managed keys
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1086` — Use double encryption for Azure Data Box in high-security environments
- `lacework-global-1099` — Storage Accounts should have shared key access disabled
- `lacework-global-1453` — Ensure Azure Log Analytics Workspaces Have Adequate Data Retention Policies
- `lacework-global-1467` — Azure Container Registries must disable public network access
- `lacework-global-1489` — Ensure Azure Automation Accounts use customer-managed keys for encryption
- `lacework-global-1510` — Azure Event Hub namespaces have public network access enabled
- `lacework-global-1523` — Ensure Azure Service Bus namespaces have local authentication disabled
- `lacework-global-1530` — Ensure Azure Cache for Redis has public network access disabled
- `lacework-global-1533` — Azure Front Door instances do not have WAF enabled
- `lacework-global-1537` — Ensure Azure API Management services use secure TLS protocols
- `lacework-global-1544` — Ensure Azure API Management services have public network access disabled when using private endpoints
- `lacework-global-1565` — Azure Container Instances should not have public IP addresses
- `lacework-global-1566` — Azure Container Instances should use customer-managed keys for encryption
- `lacework-global-1575` — Azure App Configuration stores with private endpoints should disable public network access
- `lacework-global-1586` — Azure Stream Analytics jobs are not configured with customer-managed storage accounts for private data
- `lacework-global-1607` — Ensure Azure Batch accounts have public network access disabled
- `lacework-global-1638` — Ensure Azure App Service Certificate Orders have auto-renewal enabled
- `lacework-global-1642` — Ensure Azure App Service Certificate Orders are not expired
- `lacework-global-1776` — Ensure Azure Maps accounts do not allow unrestricted CORS origins
- `lacework-global-1801` — Ensure Azure Kusto Clusters have disk encryption enabled
- `lacework-global-1807` — Ensure Azure Kusto Clusters have double encryption enabled
- `lacework-global-1935` — Ensure Azure Spring Apps is deployed in a virtual network
- `lacework-global-1953` — Ensure that 'Public Network Access' is 'Disabled' for storage accounts
- `lacework-global-2026` — Ensure Cosmos DB accounts restrict network ACL bypass
- `lacework-global-415` — Set an Expiration Time for all Keys in Role Based Access Control (RBAC) Key Vaults
- `lacework-global-416` — Set an Expiration Date for all Keys in Non Role Based Access Control (RBAC) Key Vaults
- `lacework-global-528` — Ensure that 'Secure transfer required' is set to 'Enabled'
- `lacework-global-529` — Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
- `lacework-global-530` — Ensure that Storage Account Access Keys are Periodically Regenerated
- `lacework-global-532` — Ensure that 'allowBlobPublicAccess' is 'Disabled' for storage accounts
- `lacework-global-533` — Ensure Default Network Access Rule for Storage Accounts is Set to Deny
- `lacework-global-534` — Ensure Private Endpoints are used to access Storage Accounts
- `lacework-global-538` — Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (any IP)
- `lacework-global-539` — Ensure that Microsoft Entra authentication is Configured for SQL Servers
- `lacework-global-540` — Ensure that 'Data encryption' is set to 'On' on a SQL Database
- `lacework-global-541` — Ensure that 'Auditing' Retention is 'greater than 90 days'
- `lacework-global-549` — Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled
- `lacework-global-550` — Ensure 'Infrastructure double encryption' for PostgreSQL Database Server is 'Enabled'
- `lacework-global-552` — Set 'Transport Layer Security (TLS) Version' to at least 'TLSV1.2' for Azure Database for MySQL Flexible Server
- `lacework-global-554` — Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs
- `lacework-global-555` — Ensure Diagnostic Setting captures appropriate categories
- `lacework-global-599` — Ensure That Microsoft Defender for App Services Is Set To 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-607` — Ensure That Microsoft Defender for Key Vault Is Set To 'On'
- `lacework-global-615` — Ensure that 'Enable Infrastructure Encryption' for Each Storage Account in Azure Storage is Set to 'enabled'
- `lacework-global-621` — Encrypt SQL server's Transparent Data Encryption (TDE) protector with Customer-managed key
- `lacework-global-622` — Set Microsoft Defender for SQL to 'On' for critical SQL Servers
- `lacework-global-628` — Limit 'Firewalls & Networks' to Use Selected Networks Instead of All Networks
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible
- `lacework-global-635` — Encrypt 'OS and Data' disks with Customer Managed Key
- `lacework-global-636` — Encrypt 'Unattached disks' with Customer Managed Key (CMK)
- `lacework-global-640` — Ensure that Private Endpoints are Used for Azure Key Vault
- `lacework-global-641` — Ensure automatic key rotation is enabled within Azure Key Vault
- `lacework-global-643` — Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'
- `lacework-global-947` — Ensure Azure SignalR Service instances disable public network access
- `lacework-global-994` — Configure network security groups for Databricks subnets

### Chapter 18: Network security

- `lacework-global-1023` — Ensure that 'Notify about attack paths with the following severity (or higher)' is enabled
- `lacework-global-1025` — Set the 'Agentless scanning for machines' component status to 'On'
- `lacework-global-405` — Set Microsoft Defender External Attack Surface Monitoring (EASM) to enabled
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-599` — Ensure That Microsoft Defender for App Services Is Set To 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-602` — Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'
- `lacework-global-603` — Set Microsoft Defender for Open-Source Relational Databases To 'On'
- `lacework-global-604` — Ensure That Microsoft Defender for Storage Is Set To 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-607` — Ensure That Microsoft Defender for Key Vault Is Set To 'On'
- `lacework-global-609` — Ensure That Microsoft Defender for IoT Hub Is Set To 'On'
- `lacework-global-610` — Ensure That Microsoft Defender for Resource Manager Is Set To 'On'
- `lacework-global-611` — Ensure that 'Vulnerability assessment for machines' component status is set to 'On'
- `lacework-global-612` — Set 'Agentless container vulnerability assessment' component status to 'On'
- `lacework-global-622` — Set Microsoft Defender for SQL to 'On' for critical SQL Servers

### Chapter 19: Gateway security

- `lacework-global-1016` — Capture virtual network flow logs and send them to Log Analytics
- `lacework-global-1023` — Ensure that 'Notify about attack paths with the following severity (or higher)' is enabled
- `lacework-global-1025` — Set the 'Agentless scanning for machines' component status to 'On'
- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1032` — Enable 'Default to Microsoft Entra authorization in the Azure portal'
- `lacework-global-1038` — Ensure Private Virtual Networks are used for Container Instances
- `lacework-global-1049` — Disable Public Network Access for REDIS cache
- `lacework-global-1056` — Encrypt critical data using customer-managed keys
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1066` — Enable Cross Region Restore on backup vaults
- `lacework-global-1072` — Disable Public Network Access on Recovery Services vaults
- `lacework-global-1073` — Enable Cross Region Restore on Recovery Services vaults
- `lacework-global-1096` — Set Redundancy to geo-redundant storage (GRS) on critical Azure Storage Accounts
- `lacework-global-1099` — Storage Accounts should have shared key access disabled
- `lacework-global-1132` — Ensure Operations Management Solutions are associated with a valid Log Analytics workspace
- `lacework-global-1139` — Ensure Operations Management Solutions have successfully completed provisioning
- `lacework-global-1403` — Enable Automatic OS Upgrades on Virtual Machines (VMs)
- `lacework-global-1409` — Azure Monitor Logs for Application Insights should be linked to a Log Analytics workspace
- `lacework-global-1433` — Azure Network Security Group Diagnostic Settings Not Configured for Security Monitoring
- `lacework-global-1467` — Azure Container Registries must disable public network access
- `lacework-global-1510` — Azure Event Hub namespaces have public network access enabled
- `lacework-global-1530` — Ensure Azure Cache for Redis has public network access disabled
- `lacework-global-1533` — Azure Front Door instances do not have WAF enabled
- `lacework-global-1543` — Ensure Azure API Management services have managed identities enabled
- `lacework-global-1565` — Azure Container Instances should not have public IP addresses
- `lacework-global-1582` — Ensure Azure Maintenance Configurations for InGuestPatch Include Security Update Classifications
- `lacework-global-1606` — Ensure Azure Activity Log Alerts are configured with action groups
- `lacework-global-1607` — Ensure Azure Batch accounts have public network access disabled
- `lacework-global-1642` — Ensure Azure App Service Certificate Orders are not expired
- `lacework-global-1755` — Ensure Azure Batch accounts have network profile configured with account access default action set to Deny
- `lacework-global-1933` — Ensure Azure Spring Apps has data plane public endpoint disabled
- `lacework-global-1935` — Ensure Azure Spring Apps is deployed in a virtual network
- `lacework-global-1953` — Ensure that 'Public Network Access' is 'Disabled' for storage accounts
- `lacework-global-2026` — Ensure Cosmos DB accounts restrict network ACL bypass
- `lacework-global-415` — Set an Expiration Time for all Keys in Role Based Access Control (RBAC) Key Vaults
- `lacework-global-416` — Set an Expiration Date for all Keys in Non Role Based Access Control (RBAC) Key Vaults
- `lacework-global-417` — Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults
- `lacework-global-522` — Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates
- `lacework-global-523` — Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'
- `lacework-global-525` — Ensure That 'All users with the following roles' is set to 'Owner'
- `lacework-global-526` — Ensure 'Additional email addresses' is Configured with a Security Contact Email
- `lacework-global-527` — Ensure that 'Notify about alerts with the following severity (or higher)' is enabled
- `lacework-global-529` — Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
- `lacework-global-533` — Ensure Default Network Access Rule for Storage Accounts is Set to Deny
- `lacework-global-539` — Ensure that Microsoft Entra authentication is Configured for SQL Servers
- `lacework-global-558` — Ensure that Activity Log Alert exists for Create Policy Assignment
- `lacework-global-559` — Ensure that Activity Log Alert exists for Delete Policy Assignment
- `lacework-global-560` — Ensure that Activity Log Alert exists for Create or Update Network Security Group
- `lacework-global-561` — Ensure that Activity Log Alert exists for Delete Network Security Group
- `lacework-global-562` — Ensure that Activity Log Alert exists for Create or Update Security Solution
- `lacework-global-563` — Ensure that Activity Log Alert exists for Delete Security Solution
- `lacework-global-564` — Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule
- `lacework-global-565` — Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule
- `lacework-global-566` — Ensure that Activity Log Alert exists for Create or Update Public IP Address rule
- `lacework-global-567` — Ensure that Activity Log Alert exists for Delete Public IP Address rule
- `lacework-global-568` — Ensure that RDP access from the Internet is evaluated and restricted
- `lacework-global-569` — Ensure that SSH access from the Internet is evaluated and restricted
- `lacework-global-570` — Ensure that UDP access from the Internet is evaluated and restricted
- `lacework-global-571` — Ensure that HTTP(S) access from the Internet is evaluated and restricted
- `lacework-global-572` — Ensure that Public IP addresses are Evaluated on a Periodic Basis
- `lacework-global-573` — Ensure Virtual Machines are utilizing Managed Disks
- `lacework-global-578` — Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-599` — Ensure That Microsoft Defender for App Services Is Set To 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-602` — Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'
- `lacework-global-604` — Ensure That Microsoft Defender for Storage Is Set To 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-607` — Ensure That Microsoft Defender for Key Vault Is Set To 'On'
- `lacework-global-610` — Ensure That Microsoft Defender for Resource Manager Is Set To 'On'
- `lacework-global-615` — Ensure that 'Enable Infrastructure Encryption' for Each Storage Account in Azure Storage is Set to 'enabled'
- `lacework-global-617` — Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access
- `lacework-global-628` — Limit 'Firewalls & Networks' to Use Selected Networks Instead of All Networks
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible
- `lacework-global-631` — Capture Network Security Group (NSG) Flow logs and send to Log Analytics
- `lacework-global-640` — Ensure that Private Endpoints are Used for Azure Key Vault
- `lacework-global-641` — Ensure automatic key rotation is enabled within Azure Key Vault
- `lacework-global-947` — Ensure Azure SignalR Service instances disable public network access

### Chapter 20: Data management

- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1040` — Ensure a Managed Identity is used for interactions with other Azure services
- `lacework-global-1041` — Assign roles to a Managed Identity using the principle of least privilege
- `lacework-global-1048` — Set 'System Assigned Managed Identity' to 'On'
- `lacework-global-1049` — Disable Public Network Access for REDIS cache
- `lacework-global-1059` — Disable Public Network Access for SQL servers
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1509` — Azure Event Hub namespaces do not use customer-managed keys for encryption
- `lacework-global-1510` — Azure Event Hub namespaces have public network access enabled
- `lacework-global-1511` — Azure Event Hub namespaces do not have infrastructure encryption enabled
- `lacework-global-1520` — Ensure Azure Service Bus namespaces have public network access disabled
- `lacework-global-1523` — Ensure Azure Service Bus namespaces have local authentication disabled
- `lacework-global-1530` — Ensure Azure Cache for Redis has public network access disabled
- `lacework-global-1537` — Ensure Azure API Management services use secure TLS protocols
- `lacework-global-1543` — Ensure Azure API Management services have managed identities enabled
- `lacework-global-1544` — Ensure Azure API Management services have public network access disabled when using private endpoints
- `lacework-global-1571` — Ensure Azure App Configuration stores have local authentication disabled
- `lacework-global-1575` — Azure App Configuration stores with private endpoints should disable public network access
- `lacework-global-1607` — Ensure Azure Batch accounts have public network access disabled
- `lacework-global-1755` — Ensure Azure Batch accounts have network profile configured with account access default action set to Deny
- `lacework-global-1776` — Ensure Azure Maps accounts do not allow unrestricted CORS origins
- `lacework-global-1953` — Ensure that 'Public Network Access' is 'Disabled' for storage accounts
- `lacework-global-2022` — Ensure Cosmos DB accounts have local authentication disabled
- `lacework-global-2026` — Ensure Cosmos DB accounts restrict network ACL bypass
- `lacework-global-532` — Ensure that 'allowBlobPublicAccess' is 'Disabled' for storage accounts
- `lacework-global-533` — Ensure Default Network Access Rule for Storage Accounts is Set to Deny
- `lacework-global-534` — Ensure Private Endpoints are used to access Storage Accounts
- `lacework-global-549` — Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled
- `lacework-global-568` — Ensure that RDP access from the Internet is evaluated and restricted
- `lacework-global-569` — Ensure that SSH access from the Internet is evaluated and restricted
- `lacework-global-573` — Ensure Virtual Machines are utilizing Managed Disks
- `lacework-global-582` — Enable Register with Azure Active Directory on App Service
- `lacework-global-606` — Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible
- `lacework-global-631` — Capture Network Security Group (NSG) Flow logs and send to Log Analytics
- `lacework-global-947` — Ensure Azure SignalR Service instances disable public network access
- `lacework-global-994` — Configure network security groups for Databricks subnets

### Chapter 22: Enterprise systems security

- `lacework-global-1030` — Disable Public Network Access when using a Private Endpoint
- `lacework-global-1061` — Ensure Azure Kubernetes Service (AKS) clusters have Role-Based Access Control (RBAC) enabled
- `lacework-global-1062` — Enable soft delete on backup vaults
- `lacework-global-1068` — Enable soft delete on Recovery Services vaults
- `lacework-global-1069` — Enable immutability for Recovery Services vaults
- `lacework-global-1070` — Encrypt backup data in Recovery Services vaults using CMK
- `lacework-global-1073` — Enable Cross Region Restore on Recovery Services vaults
- `lacework-global-1096` — Set Redundancy to geo-redundant storage (GRS) on critical Azure Storage Accounts
- `lacework-global-1112` — Ensure Azure Arc-enabled SQL Server instances have automated backup policies configured
- `lacework-global-1395` — Enable Confidential Computing on Virtual Machines (VMs)
- `lacework-global-1453` — Ensure Azure Log Analytics Workspaces Have Adequate Data Retention Policies
- `lacework-global-1533` — Azure Front Door instances do not have WAF enabled
- `lacework-global-1573` — Azure SQL virtual machines should have auto backup encryption enabled
- `lacework-global-1787` — Ensure Azure Managed Applications have JIT access enabled
- `lacework-global-1881` — Ensure Azure Arc-enabled Kubernetes clusters have automatic agent upgrades enabled
- `lacework-global-1899` — Ensure Azure Kubernetes Extensions Have Auto-Upgrade for Minor Versions Enabled
- `lacework-global-397` — Ensure that Stock Keeping Unit (SKU) Basic/Consumption is not used on artifacts requiring monitoring (Particularly for Production Workloads)
- `lacework-global-541` — Ensure that 'Auditing' Retention is 'greater than 90 days'
- `lacework-global-542` — Set Vulnerability Assessment (VA) setting 'Also send email notifications to admins and subscription owners' for each SQL Server
- `lacework-global-549` — Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled
- `lacework-global-553` — Enable Azure Monitor Resource Logging for All Services that Support it
- `lacework-global-554` — Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs
- `lacework-global-555` — Ensure Diagnostic Setting captures appropriate categories
- `lacework-global-568` — Ensure that RDP access from the Internet is evaluated and restricted
- `lacework-global-569` — Ensure that SSH access from the Internet is evaluated and restricted
- `lacework-global-579` — Ensure the Key Vault is Recoverable
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-601` — Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
- `lacework-global-605` — Set Microsoft Defender for Containers To 'On'
- `lacework-global-614` — Ensure that 'Endpoint protection' component status is set to 'On'
- `lacework-global-623` — Enable Vulnerability Assessment (VA) on a SQL server by setting a Storage Account
- `lacework-global-624` — Set Vulnerability Assessment (VA) setting 'Periodic recurring scans' to 'on' for each SQL server
- `lacework-global-625` — Configure Vulnerability Assessment (VA) setting 'Send scan reports to' for a SQL server
- `lacework-global-629` — Ensure That Private Endpoints Are Used Where Possible
- `lacework-global-633` — Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'
- `lacework-global-637` — Ensure that Endpoint Protection for all Virtual Machines is installed

### Chapter 23: Public Cloud Security

- `lacework-global-1453` — Ensure Azure Log Analytics Workspaces Have Adequate Data Retention Policies
- `lacework-global-541` — Ensure that 'Auditing' Retention is 'greater than 90 days'
- `lacework-global-553` — Enable Azure Monitor Resource Logging for All Services that Support it
- `lacework-global-554` — Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs
- `lacework-global-555` — Ensure Diagnostic Setting captures appropriate categories
- `lacework-global-598` — Set Microsoft Defender for Servers to 'On'
- `lacework-global-614` — Ensure that 'Endpoint protection' component status is set to 'On'
- `lacework-global-637` — Ensure that Endpoint Protection for all Virtual Machines is installed

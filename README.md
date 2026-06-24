# FortiCNAPP NZISM v3.7 Custom Compliance Framework

Custom FortiCNAPP compliance framework mapping the New Zealand Information Security Manual (NZISM) Restricted v3.7 to Azure CSPM policies.

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

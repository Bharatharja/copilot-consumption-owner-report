#Provided as a sample for testing, without warranty or a support commitment. Review and validate it in your environment before use.
# Copilot Studio Consumption and Owner Report: Test Instructions

## Purpose

`Export-CopilotStudioConsumptionOwners.ps1` enriches a Power Platform admin
center (PPAC) agent consumption CSV with current agent owner names, email/UPNs,
owner types (user or team), and IDs. It matches records by environment ID and
agent ID and exports a new CSV, retaining unmatched rows for review.

The script does not change cloud resources or the input report. Consumption
dates come from the downloaded CSV; ownership reflects the time the script
runs. Downloading the report and signing in are manual steps.

## Before you start

- Use **PowerShell 7.2 or later**. No additional PowerShell modules are required.
- Download a **nonempty agent-level consumption CSV** from
  **PPAC > Licensing > Copilot Studio > Download report**. Keep its original
  column headers.
- Use a single-tenant **Microsoft Entra app registration** configured for
  public-client authentication. Under **Authentication**, add **Mobile and
  desktop applications**, select
  `https://login.microsoftonline.com/common/oauth2/nativeclient`, and set
  **Allow public client flows** to **Yes**. No secret or certificate is needed.
- Add the following **delegated permissions** and have an authorized
  administrator grant tenant admin consent:

| API | Delegated permission |
|---|---|
| Power Platform API | `EnvironmentManagement.Environments.Read` |
| Dynamics CRM | `user_impersonation` |

To find Power Platform API, search **APIs my organization uses** for
`8578e004-a5c6-46e7-913e-12f58912df43`.

The app registration identifies the application; interactive sign-in supplies
the user's access rights. The user must be able to view the relevant
environments and read Dataverse **Bot, User, and Team** records. Global
Administrator access is not required, and tenant admin roles alone do not
guarantee Dataverse access. Any environment-level application restrictions
must also allow this app.

**Scope:** Microsoft public cloud only. Device-code sign-in must be permitted
by the customer's access policies. The script is read-only, but
`user_impersonation` itself is not a read-only permission; use a suitably
restricted reporting account where possible.

## Run

Open PowerShell 7 in the folder containing the script. Replace the IDs and
paths below, then complete the displayed Microsoft device-code sign-in:

```powershell
.\Export-CopilotStudioConsumptionOwners.ps1 `
    -ClientId 'APPLICATION-CLIENT-ID' `
    -TenantId 'DIRECTORY-TENANT-ID' `
    -ConsumptionCsvPath 'C:\Reports\AgentConsumption.csv' `
    -OutputPath 'C:\Reports\CopilotConsumptionWithOwners.csv'
```

Use a **new output filename**. Matching input/output paths are rejected, but
an existing output file can be overwritten. Store the result in an approved
location because it contains consumption and owner contact information.

## Validate the test

Start with a report containing a known agent. Confirm the output has the same
number of rows and billed/non-billed credit values as the source. Compare the
known agent's owner with the current Dataverse/Copilot Studio owner. Review
all console warnings and the `JoinStatus` column:

| JoinStatus | Meaning / action |
|---|---|
| `Matched` | Agent found. Owner contact fields can still be blank; verify them. |
| `EnvironmentNotVisible` | Environment was not returned for the signed-in user; check environment ID and access. |
| `EnvironmentHasNoDataverseUrl` | No Dataverse URL was returned for the environment. |
| `EnvironmentReadFailed` | Inventory could not be read; inspect the console warning. |
| `AgentNotFound` | Inventory was read, but no visible agent matched the ID; check deleted agents, record access, or non-bot resources. |

For **403 "Access to Dataverse API is restricted for this application ID"**,
ask the environment administrator to check application-access restrictions
using the app ID and environment URL in the warning. Other Dataverse access
errors may require a suitable read security role.

A completed export does not mean every owner was resolved. Review unmatched
rows before using the report for owner follow-up.

Watch me explain this lab: [LoomLink](PASTE-VIDEO-LINK-HERE)

# terraform-azure-update-manager

Used Terraform and PowerShell to deploy a three-server Windows domain on Azure and put it under Azure Update Manager: Azure Policy turns on daily patch assessment, a weekly maintenance window patches Critical, Security, and Update Rollup updates, and a validation script reports PASS/FAIL per server with a JSON export. I built the servers from a three-month-old Windows Server image on purpose, so the first compliance check came back **FAIL with 2 missing security updates on every server**. A patch deployment brought all three to **PASS with 0 missing**, and the scheduled window then ran on its own. Getting there meant fixing a guide whose scheduled patching could never have fired, whose validation script called a cmdlet that doesn't exist, and whose "fresh VMs will show FAIL" assumption turned out to be wrong.

# Cloud Systems Administration, Lab 3: Azure Update Manager

**Terraform · Azure Update Manager · Azure Policy · Maintenance Configurations · Active Directory · Azure CLI · PowerShell**

Lab 1 controlled who can open files inside a server. Lab 2 controlled who can manage the server from Azure. This lab answers the question that comes after both: is the server actually patched, and can I prove it? An unpatched server with perfect NTFS and RBAC permissions is still the easiest way into a network. Azure Update Manager is how Azure assesses, schedules, and reports patching across VMs, and this lab builds it end to end with code, then proves it with a real before and after.

This is the third and final lab of a three lab Cloud Systems Administration series, following the [Lab 1 NTFS File Server](https://github.com/richardkmnguyen/terraform-azure-ntfs-file-server) and [Lab 2 Azure RBAC](https://github.com/richardkmnguyen/terraform-azure-rbac-access-control). Unlike Lab 2, it is standalone: it deploys its own domain and shares only the remote state storage account with the other two labs.

| | |
|---|---|
| **Platform** | Terraform, Azure CLI, and PowerShell on a local Windows PC, against East US on my personal Azure subscription |
| **Time** | 4 hours |

---

## What this lab is for

The business problem: a critical Windows vulnerability is announced and the security team needs every server patched within 48 hours. Before that can happen, someone has to answer three questions: which servers are missing the patch, how do we install it without breaking anything, and how do we prove afterwards that it worked? Doing that by hand, server by server, doesn't scale and leaves no record.

Four ideas make that work:

- **Assess continuously, not once.** Periodic assessment checks every server for missing updates every 24 hours. Azure Policy turns it on automatically for any VM in the resource group, so a new server can't be forgotten.
- **Patch on a schedule you control.** A maintenance configuration defines *when* (a weekly window) and *what* (which update classifications). Assigning it to a VM puts that VM on the schedule.
- **Patch orchestration has to be set to match.** Azure only follows your schedule if the VM's patch mode says so. Left on the default, Windows Update patches on its own and the schedule is ignored.
- **Prove it with data, not screenshots alone.** A validation script reads each VM's latest assessment from Azure, marks it PASS or FAIL, and exports a JSON report that could feed a SIEM, ServiceNow, or a compliance dashboard.

| Server | Role | Patch order |
|---|---|---|
| `DC01` | Domain controller for `aumlab.local`, DNS, static IP 10.0.1.4 | Last: everything depends on it |
| `WS01` | Domain-joined member server | First |
| `WS02` | Domain-joined member server | First |

---

## Architecture

```
My local Windows PC (PowerShell, Azure CLI, Terraform)
        │
        │  Terraform calls the Azure management API
        │  State stored remotely under its own key (aum-lab.tfstate)
        ▼
Azure subscription (personal)
        │
        ├── RG-TerraformState: one storage account, one state file per lab
        │       ntfs-lab / rbac-lab / aum-lab.tfstate
        │
        └── rg-aumlab (East US)
                │
                ├── vnet-aumlab / snet-aumlab 10.0.1.0/24 + NSG (RDP from my IP only)
                ├── Key Vault (RBAC mode): admin password stored as a secret
                │
                ├── DC01  10.0.1.4   AD DS + DNS (aumlab.local)
                ├── WS01  DNS → DC01, joined to aumlab.local
                ├── WS02  DNS → DC01, joined to aumlab.local
                │     all three: patch mode AutomaticByPlatform + "Customer Managed Schedules"
                │
                ├── Azure Policy: periodic assessment (every 24h), system-assigned identity
                └── Maintenance configuration: aum-weekly-patches
                        Sunday, 3-hour window, Pacific time
                        Critical + Security + UpdateRollup, reboot if required
                        assigned to DC01, WS01, WS02
```

<!-- SCREENSHOT: Lab 3 AUM architecture diagram from the SOP -->

| Component | Role |
|---|---|
| **`modules/networking`** | VNet, subnet, NSG allowing RDP only from my public IP, and the subnet–NSG association |
| **`modules/keyvault`** | RBAC-mode Key Vault, a Secrets Officer role for me, a 90-second wait for the role to propagate, and the admin password secret |
| **`modules/compute`** | Three Windows Server 2022 VMs with Update Manager patch settings, DC promotion on DC01, and domain join on WS01/WS02 |
| **`modules/update-manager`** | Policy assignment for periodic assessment, the weekly maintenance configuration, and one assignment per VM |
| **Remote state** | Same storage account as Labs 1 and 2, its own key, so the labs can never touch each other |
| **`validate-lab.ps1`** | Reads each VM's latest assessment and last install from Azure, prints PASS/FAIL, exports `aum-compliance-report.json` |

Key concepts I needed:

- **Assessment vs. installation.** Assessment only lists what's missing. Installation is a separate operation, either on a schedule or on demand.
- **Patch orchestration.** Scheduled patching requires `patchMode = AutomaticByPlatform` *and* `bypassPlatformSafetyChecksOnUserSchedule = true` (shown in the portal as "Customer Managed Schedules"). Without the second flag, Azure auto-patches on its own timing instead of yours.
- **Update classifications.** Windows updates are tagged Critical, Security, Update Rollup, Definition, and others. The schedule and the compliance check only care about the first three.
- **Policy effects need an identity.** A policy that changes resources (Modify or DeployIfNotExists) must have a managed identity with a role, or Azure rejects the assignment.

---

## What I built

### 1. Fixed the guide's Terraform before running it
Most of the guide's `.tf` files used one-line blocks with several arguments, which Terraform can't parse. Same fix as Labs 1 and 2: one argument per line. While doing that, I checked every resource against how Azure actually behaves and found several things that would have deployed but never worked (see [The errors](#the-errors-one-at-a-time)). I also moved the VM size, image version, and maintenance start time into `terraform.tfvars`, so I could change them without editing module code.

### 2. Set the patch settings Update Manager actually needs
The guide created the VMs with default patch settings, which means Windows patches itself and the maintenance schedule never runs. Each VM now sets the patch orchestration that scheduled patching requires, and turns on periodic assessment directly so it works from the first minute instead of waiting for Azure Policy:

```hcl
resource "azurerm_windows_virtual_machine" "dc01" {
  name = "DC01"
  size = var.vm_size
  # ...
  patch_mode                                             = "AutomaticByPlatform"
  patch_assessment_mode                                  = "AutomaticByPlatform"
  bypass_platform_safety_checks_on_user_schedule_enabled = true
  vm_agent_platform_updates_enabled                      = true

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = var.image_version
  }
}
```

### 3. Built the domain without in-guest network changes
DC01 gets a static private IP, and WS01/WS02 get DC01 as their DNS server **on the Azure network interface** instead of inside Windows. Picking a network adapter inside Windows is exactly what broke a domain join in Lab 1. The extension scripts also changed:

- **Passwords go in `protected_settings`**, which is encrypted and hidden from anyone with Reader access. The guide used plain `settings`, visible in the portal, and hardcoded the DSRM password in the file.
- **Each script exits cleanly, then reboots 60 seconds later.** If a server reboots while its extension is still running, Azure can mark the extension failed even though promotion worked, and a re-apply would try to promote an existing DC.
- **The domain join waits for DNS (up to 15 minutes) and retries `Add-Computer` for up to 10 minutes**, because DC01 answering DNS doesn't mean Active Directory is ready yet.

### 4. Enrolled the VMs in Update Manager
The policy assignment needed a managed identity and a role to work at all. The maintenance configuration is the schedule, and one assignment per VM puts each server on it:

```hcl
resource "azurerm_resource_group_policy_assignment" "aum_assessment" {
  name                 = "aum-periodic-assessment"
  resource_group_id    = var.resource_group_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/59efceea-0c96-497e-a4a1-4eb2290dac15"
  location             = var.location

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_maintenance_configuration" "weekly" {
  name                     = "aum-weekly-patches"
  scope                    = "InGuestPatch"
  in_guest_user_patch_mode = "User"
  # ...
  window {
    start_date_time = var.maintenance_start
    time_zone       = var.maintenance_time_zone
    duration        = "03:00"
    recur_every     = "Week Sunday"
  }

  install_patches {
    reboot = "IfRequired"
    windows {
      classifications_to_include = ["Critical", "Security", "UpdateRollup"]
    }
  }
}
```

### 5. Deployed
`terraform plan` showed 28 resources. The first apply created 19 and then failed on all three VMs with `SkuNotAvailable` (below). After switching sizes, the second apply added the remaining 9. All three extensions reported `Succeeded`: DC01 was promoted and WS01/WS02 joined `aumlab.local`.

<img width="351" height="182" alt="AUMTerraformPlanChanges" src="https://github.com/user-attachments/assets/f422620c-1a6c-4296-b4e9-7e33a3932891" />
<img width="1910" height="365" alt="AUMQuotaError" src="https://github.com/user-attachments/assets/5eafacfc-9dc1-4669-b942-ad5635672a50" />
<img width="598" height="138" alt="AUMTerraformPlanNoChangesAndOutput" src="https://github.com/user-attachments/assets/12de7bf5-96fd-4d65-9777-cc15924a1e86" />

> I accidently closed my PowerShell window before I got the screenshot of the apply adding the remaining 9 resources as well as all 3 extensions reporting `Succeeded`. However, I reran Terraform Plan and Output in another PowerShell Window to showcase everything was configured properly and built.

### 6. Got a real FAIL: rebuilt from an older image
The first compliance check came back **PASS** on every server: 0 Critical/Security updates missing. The `latest` Windows Server image in Azure is rebuilt every month with that month's updates, so a fresh VM starts out fully patched. The guide (and my own first plan) assumed fresh VMs would show FAIL.

A lab that only ever shows PASS doesn't prove the process works, so I pinned the image to the July 2026 release:

```powershell
az vm image list --publisher MicrosoftWindowsServer --offer WindowsServer --sku 2022-datacenter --all --location eastus --query "[].version" -o tsv
az vm image show --urn "MicrosoftWindowsServer:WindowsServer:2022-Datacenter:20348.5386.260711" --query "{name:name, gen:hyperVGeneration}" -o table
```

Changing `image_version` forces Azure to rebuild each VM, and Terraform rebuilt *only* what depends on them: `9 to add, 1 to change, 9 to destroy` (3 VMs, 3 extensions, 3 maintenance assignments, plus the schedule's new start time). The network, Key Vault, policy, and public IPs were kept.

<img width="608" height="116" alt="AUMValidateScriptPass" src="https://github.com/user-attachments/assets/2615469e-8354-417b-a996-848d4be1925e" />
<img width="307" height="118" alt="AUMApplyPart2" src="https://github.com/user-attachments/assets/d31bacf4-8d7e-4d6f-861c-94b37471cc0b" />
<img width="791" height="259" alt="AUMImageTable" src="https://github.com/user-attachments/assets/17c3afc9-813d-4d3c-8992-e441eed42e6f" />

> All three VMs are on 20348.5386.260711, an older Windows Server image.

### 7. Assessed: FAIL
I triggered an on-demand assessment on all three servers and ran the validation script:

```powershell
foreach ($vm in "DC01","WS01","WS02") {
  az rest --method POST `
    --url "https://management.azure.com/subscriptions/$subId/resourceGroups/rg-aumlab/providers/Microsoft.Compute/virtualMachines/$vm/assessPatches?api-version=2022-03-01"
}
./scripts/validate-lab.ps1 -ResourceGroup rg-aumlab -SubscriptionId $subId
```

```
[FAIL] DC01 -- Critical/Security missing: 2 | Other: 2 | Assessment: Succeeded | Last install: none
[FAIL] WS01 -- Critical/Security missing: 2 | Other: 2 | Assessment: Succeeded | Last install: none
[FAIL] WS02 -- Critical/Security missing: 2 | Other: 2 | Assessment: Succeeded | Last install: none
Overall: FAILURES DETECTED
```

The missing updates on each server:

| KB | Classification | Update |
|---|---|---|
| KB5126655 | Security | 2026-10 Cumulative Update for Windows Server 2022 (21H2) |
| KB5128928 | Security | 2026-10 Cumulative Update for .NET Framework 3.5, 4.8, 4.8.1 |
| KB890830 | Update Rollup | Windows Malicious Software Removal Tool v5.146 |
| KB2267602 | Definition | Microsoft Defender Antivirus security intelligence update |

<img width="601" height="124" alt="AUMValidateFail" src="https://github.com/user-attachments/assets/be84a557-96ea-49c5-b253-1d7224f80cc7" />
<img width="857" height="102" alt="AUMKBNames" src="https://github.com/user-attachments/assets/116a7a1e-c06d-47ff-8c98-2a2a81d1bf72" />

### 8. Patched: member servers first, DC last
This is the emergency patch workflow from the business problem: a one time deployment of the same classifications the weekly schedule uses, with a 2 hour limit and a reboot only if required.

```powershell
'{"maximumDuration":"PT2H","rebootSetting":"IfRequired","windowsParameters":{"classificationsToInclude":["Critical","Security","UpdateRollup"]}}' |
  Out-File install-body.json -Encoding ascii

foreach ($vm in "WS01","WS02","DC01") {
  az rest --method POST `
    --url "https://management.azure.com/subscriptions/$subId/resourceGroups/rg-aumlab/providers/Microsoft.Compute/virtualMachines/$vm/installPatches?api-version=2022-03-01" `
    --body "@install-body.json"
}
```

All three finished in about 45 minutes: **3 installed, 0 failed** each (both security updates plus the Malicious Software Removal Tool).

<img width="902" height="178" alt="AUMInstallInProgress" src="https://github.com/user-attachments/assets/ccee508d-7412-4a21-8131-d72643475fd1" />
<img width="905" height="179" alt="AUMInstallSucceeded" src="https://github.com/user-attachments/assets/4c883258-dbbc-405e-b98f-0d138083db35" />
<img width="1919" height="346" alt="AUMAzureUpdateManagerSucceeded" src="https://github.com/user-attachments/assets/ed5ba37e-b4d4-4c6c-bd42-347bfdfd526c" />

### 9. Re-assessed: PASS

```
[PASS] DC01 -- Critical/Security missing: 0 | Other: 1 | Assessment: Succeeded | Last install: Succeeded
[PASS] WS01 -- Critical/Security missing: 0 | Other: 1 | Assessment: Succeeded | Last install: Succeeded
[PASS] WS02 -- Critical/Security missing: 0 | Other: 1 | Assessment: Succeeded | Last install: Succeeded
Overall: ALL PASS
```

| Server | Critical/Security before | After | Other before | After | Installed |
|---|---|---|---|---|---|
| DC01 | 2 | **0** | 2 | 1 | 3 |
| WS01 | 2 | **0** | 2 | 1 | 3 |
| WS02 | 2 | **0** | 2 | 1 | 3 |

The one remaining "Other" update is the Defender definition, a classification outside the schedule and the compliance rule. Both reports will be saved in the repo as [`aum-compliance-report-before.json`](aum-compliance-report-before.json) and [`aum-compliance-report-after.json`](aum-compliance-report-after.json).

<img width="602" height="123" alt="AUMValidateSucceed" src="https://github.com/user-attachments/assets/ba421dc6-9776-4bb8-8ecf-4e3a40e85c80" />

> Same three servers, same script, an hour apart: 2 missing security updates to 0. That before and after is the whole point of the lab, and it only exists because I didn't accept the first PASS.

### 10. Watched the schedule run on its own
Verifying the schedule exists is one thing; seeing it fire is another. I moved the first window to 2:30 AM, applied (`0 added, 1 changed, 0 destroyed`), and watched Update Manager History. The run started on time, triggered by `aum-weekly-patches` rather than by me, and checked all three servers. With everything already patched, there was nothing left in scope to install.

<img width="686" height="284" alt="AUMWeeklyPatchesNew" src="https://github.com/user-attachments/assets/acce256e-d9e6-4d6d-ac4e-71ca3685049d" />
<img width="1920" height="425" alt="AUMUpdateManagerMachines" src="https://github.com/user-attachments/assets/a4e8a9fa-0128-4a81-9b33-50eba0da552c" />
<img width="1919" height="342" alt="AUMScheduledMaintenance" src="https://github.com/user-attachments/assets/a05414c3-cf58-4524-b768-a75d26ab6871" />
<img width="1907" height="709" alt="AUMScheduledMaintenanceID" src="https://github.com/user-attachments/assets/2dd63a7b-a600-435a-a4ab-c428641f4475" />
<img width="1918" height="585" alt="AUMCompliant" src="https://github.com/user-attachments/assets/77157c8f-e3b4-43a7-81b2-74a41b4d8fa8" />

---

## The errors, one at a time

### The guide's scheduled patching could never have run
The guide created the maintenance configuration and assigned it to every VM, but left the VMs on the default patch mode (`AutomaticByOS`). Scheduled patching only applies when the VM is set to `AutomaticByPlatform` with `bypass_platform_safety_checks_on_user_schedule_enabled = true`. Everything would have deployed green, the portal would have shown the schedule assigned, and the window would never have patched anything, while Windows Update kept patching on its own timing. I added both settings to all three VMs.

### The validation script called a cmdlet that doesn't exist
The guide's `validate-lab.ps1` used `Get-AzVMPatchAssessmentResult`, which isn't in the Az module. Every VM would have reported blank fields and FAIL forever, and the guide's troubleshooting table said to just wait longer. The real data lives in the VM's instance view, so the script now reads it from there:

```powershell
$view       = Get-AzVM -ResourceGroupName $ResourceGroup -Name $vm -Status
$assessment = $view.PatchStatus.AvailablePatchSummary
$install    = $view.PatchStatus.LastPatchInstallationSummary
$compliant  = ($assessment.Status -eq "Succeeded") -and ($assessment.CriticalAndSecurityPatchCount -eq 0)
```

### The policy assignment had no identity
The built-in policy *Configure periodic checking for missing system updates on azure virtual machines* uses the Modify effect: it changes VM settings. Azure rejects that kind of assignment without a managed identity. I added a system-assigned identity, a location, and a Virtual Machine Contributor role so the policy can remediate VMs.

### The schedule's start date was already in the past
The guide hardcoded `start_date_time = "2026-08-01 02:00"` in Eastern time. By the time I ran the lab that date had passed, and 2:00 AM Eastern is 11:00 PM Pacific. I moved the start date and time zone into `terraform.tfvars`.

### `SkuNotAvailable`: Standard_B2s was sold out
```
SkuNotAvailable: The requested VM size for resource 'Following SKUs have failed for Capacity Restrictions: Standard_B2s' is currently not available in location 'eastus'.
```
I had checked beforehand: no restrictions on B2s and 10 B-series vCPUs of quota free. But that check only shows *permanent* restrictions, not sizes that are temporarily out of capacity. The first apply created 19 resources and failed only on the VMs, so nothing needed cleaning up. Two fallback sizes (D2s_v5, D2as_v5) had a quota of 0 on my subscription. **Standard_D2s_v4** had quota and capacity, and it supports the Gen1 image and SCSI disk controller this lab uses, unlike the v6/v7 sizes I used in Lab 1. The second apply added only the missing 9 resources.

### Drift on every plan: `vm_agent_platform_updates_enabled`
After a successful apply, `terraform plan` wanted to change all three VMs:

```
~ vm_agent_platform_updates_enabled = true -> false
Plan: 0 to add, 3 to change, 0 to destroy.
```
<img width="1763" height="503" alt="AUMDrift" src="https://github.com/user-attachments/assets/e09b4707-a74b-46c8-9dbd-2964d0add148" />

When patch mode is `AutomaticByPlatform`, Azure turns this setting on by itself. The azurerm 3.x provider defaults it to `false`, so every plan tries to turn it back off, and Azure would just turn it on again. I set it to `true` explicitly in the code so the code matches reality, and the next plan came back "No changes."

### Fresh VMs were already compliant
Covered in [step 6](#6-got-a-real-fail-rebuilt-from-an-older-image): the `latest` image already contained October's updates, so the "before" check was PASS. Pinning the image to July's release gave a real FAIL.

### The script wasn't digitally signed
```
validate-lab.ps1 is not digitally signed. You cannot run this script on the current system.
```
Windows marks files that came from the internet, and this execution policy blocks them. `Unblock-File .\scripts\validate-lab.ps1` cleared the mark.

### Smaller fixes from the guide
- **Key Vault 403 on first apply:** `depends_on` orders the role assignment before the secret but doesn't wait for RBAC to propagate. Added a 90 second `time_sleep`.
- **The domain join wait loop had no limit** despite the guide saying "3 minutes." Capped it.
- **`echo $env:TF_VAR_admin_password`** prints the password on screen. Used `[bool]$env:TF_VAR_admin_password` instead.
- **NuGet prompt during `Install-Module Az`:** normal on Windows PowerShell 5.1. I ran the whole lab in one PowerShell version so the Az module was always available.

---

## Problems and fixes

| What broke | Cause | Fix |
|---|---|---|
| Schedule would never patch | VMs on default `AutomaticByOS` patch mode | `AutomaticByPlatform` + `bypass_platform_safety_checks_on_user_schedule_enabled = true` |
| Validation always FAIL with blank fields | `Get-AzVMPatchAssessmentResult` doesn't exist | Read `Get-AzVM -Status` → `PatchStatus` |
| Policy assignment rejected | Modify-effect policy with no managed identity | System-assigned identity + Virtual Machine Contributor role |
| Schedule start in the past, wrong time zone | Hardcoded `2026-08-01 02:00` Eastern | Start date and time zone moved to `terraform.tfvars` |
| One-line blocks rejected | Several arguments on one line | One argument per line |
| Passwords visible in the portal and repo | Plain extension `settings`, hardcoded DSRM password | `protected_settings`, password from a variable |
| `SkuNotAvailable` on all VMs | Standard_B2s out of capacity in East US | `vm_size = "Standard_D2s_v4"` (quota and Gen1 support checked first) |
| Plan wanted to change all 3 VMs | Azure enables `vm_agent_platform_updates_enabled`; provider defaults to `false` | Set it to `true` in code |
| "Before" check was PASS | `latest` image already patched | Pinned image `20348.5386.260711` (July 2026) |
| Script blocked | Downloaded file, execution policy | `Unblock-File` |
| Key Vault 403 risk on first apply | RBAC propagation delay | `time_sleep` 90s |

---

## Key takeaways

1. **"Assigned" isn't "working."** The guide's schedule would have shown up in the portal, assigned to every VM, and never patched anything. The VM's patch orchestration setting is what makes the schedule real.
2. **Don't trust a PASS you didn't earn.** Fresh VMs passing compliance looked like success. It actually meant the test couldn't fail. Rebuilding from an older image proved the whole loop: detect, patch, verify.
3. **A validation script has to fail loudly when it can't see.** Blank data reported as FAIL looks exactly like a real finding. Stopping with "not signed in" is more honest than a confident wrong answer.
4. **Pre-checks have limits.** The SKU restriction check passed and the deploy still failed on capacity. Know what a check actually covers, and keep the size in a variable so the fix is one line.
5. **Make the code match what Azure does.** The drift on `vm_agent_platform_updates_enabled` wasn't a real change. It was Terraform and Azure disagreeing about a default. Writing the real value into code is better than ignoring the diff.
6. **Patch member servers before the domain controller.** If an update breaks something, it breaks on a server that isn't holding up authentication for everyone else.
7. **Terraform rebuilt only what had to change.** Changing the image version replaced 9 resources and kept 19, and the plan said so before anything happened.

If I did this again, I would check the Azure image release cadence before planning a "before" state, check capacity in two regions before choosing one, and keep every session in a single PowerShell window with a transcript running from the start.

---

## Security notes

This is a lab configuration. Some of it is solid and some of it would not be acceptable in production:

**What the lab does well**
- **Every server is assessed daily and on a patch schedule,** enforced by Azure Policy for anything new in the resource group.
- **The admin password never touches a file.** It comes from an environment variable, lives in Key Vault, and reaches the VMs only through encrypted `protected_settings`.
- **RDP is limited to my public IP** by an NSG associated with the subnet.
- **Separate state per lab,** so destroying this lab can't touch Labs 1 or 2.
- **`terraform.tfvars`, state files, and plans are in `.gitignore`.**

**What I would change for production**
- **Remove public IPs and RDP from the internet.** Use Azure Bastion or a VPN.
- **Use rings for patching,** e.g. a pilot group a few days before production, with separate maintenance configurations and dynamic scopes based on tags instead of per-VM assignments.
- **Separate credentials:** the local admin, domain admin, and DSRM passwords are all the same here.
- **Send patch compliance to monitoring:** Azure Resource Graph queries or an Azure Monitor alert when Critical/Security counts are above 0, instead of a script I run by hand.
- **Pre- and post-maintenance tasks** (snapshots before patching, service checks after) using maintenance configuration events.

---

## Verification

| Check | How I verified it |
|---|---|
| Configuration valid | `terraform validate` succeeded |
| Full deployment | 28 resources in state (29 entries including one data source) |
| Domain built | `SetupDC` and both `JoinDomain` extensions `Succeeded` |
| Code matches Azure | `terraform plan`: "No changes" after the drift fix |
| VMs on the older image | `az vm list` showed `20348.5386.260711` on all three |
| Assessment works | All three `Succeeded`; 2 Critical/Security missing each |
| Patching works | One-time install: 3 installed, 0 failed on each |
| Compliance proven | `validate-lab.ps1`: FAIL (before) → ALL PASS (after), JSON reports exported |
| Schedule assigned | `aum-weekly-patches` Machines tab: DC01, WS01, WS02 |
| Schedule runs on its own | Update Manager History: scheduled run by `aum-weekly-patches` |
| Policy enforced | Policy compliance for `aum-periodic-assessment` |
| Patch orchestration correct | Update Manager Machines: Customer Managed Schedules, periodic assessment on |

<img width="401" height="461" alt="AUMInitValidate" src="https://github.com/user-attachments/assets/fd7dc0de-ae28-4e1a-9f4c-22e1a9ca4d97" />
<img width="1919" height="705" alt="AUMDC01SetUpDCSucceeded" src="https://github.com/user-attachments/assets/9b6e1def-dca1-4210-8501-e2bd9b66113a" />
<img width="1918" height="700" alt="AUMWS01JoinDomainSucceeded" src="https://github.com/user-attachments/assets/cf569817-08f9-4d3a-baa2-ec800ac6eb8c" />
<img width="1918" height="701" alt="AUMWS02JoinDomainSucceeded" src="https://github.com/user-attachments/assets/88a72670-2db9-4113-8f77-f8e7f9178359" />
<img width="791" height="259" alt="AUMImageTable" src="https://github.com/user-attachments/assets/dd7ecab6-bea4-4c02-9de6-61cc0b7d8d36" />
<img width="1920" height="341" alt="AUMAzureUpdateManagerAssessmentSucceeded" src="https://github.com/user-attachments/assets/56dd4679-8937-414c-a727-7dbf3e965c4d" />
<img width="601" height="124" alt="AUMValidateFail" src="https://github.com/user-attachments/assets/264a5bed-a542-40a3-908b-29a0d954a297" />
<img width="602" height="123" alt="AUMValidateSucceed" src="https://github.com/user-attachments/assets/fc3fa0dc-c29b-45ce-82b3-53b233faa9a5" />
<img width="1691" height="292" alt="AUMWeeklyPatchesMachines" src="https://github.com/user-attachments/assets/1c034c30-fd42-4787-b9af-9b075de062c2" />
<img width="686" height="284" alt="AUMWeeklyPatchesNew" src="https://github.com/user-attachments/assets/59095271-287c-48cc-87d1-6faef2aa9079" />
<img width="1918" height="585" alt="AUMCompliant" src="https://github.com/user-attachments/assets/79f18c1b-7d90-4237-ae0e-90bc4d2f33e5" />

---

## Teardown

The VMs are deallocated for now so I can record a video, which stops compute charges. Disks and static public IPs still bill (about $1/day), so the lab gets destroyed once the video is done.

```powershell
# Pause: stops compute charges (deallocate, not just stop)
az vm deallocate --ids $(az vm list -g rg-aumlab --query "[].id" -o tsv)

# Resume for filming
az vm start --ids $(az vm list -g rg-aumlab --query "[].id" -o tsv)

# Remove everything this lab created (Labs 1 and 2 untouched)
terraform destroy
az group show --name rg-aumlab   # expect ResourceGroupNotFound
```

While the VMs are deallocated, the Sunday maintenance window still fires but can't patch them, so History shows those runs as not completed. That's expected.

<img width="606" height="157" alt="AUMDeallocated" src="https://github.com/user-attachments/assets/aa068aa8-8c21-4712-bfc4-59dbd1fb7ffc" />

---

## Repository structure

```
azure-update-manager-lab/
├── backend.tf                      remote state (own key)
├── versions.tf                     azurerm ~> 3.100, random, time
├── variables.tf                    vm_size, image_version, maintenance_start, ...
├── main.tf                         wires the four modules
├── outputs.tf                      public IPs, Key Vault name
├── terraform.tfvars.example        copy to terraform.tfvars and fill in
├── modules/
│   ├── networking/main.tf
│   ├── keyvault/main.tf
│   ├── compute/main.tf
│   └── update-manager/main.tf
├── scripts/
│   └── validate-lab.ps1
├── aum-compliance-report-before.json
├── aum-compliance-report-after.json
└── SOP-CHANGES.md                  every change from the original guide, with reasons
```

---

## Next steps

- Split patching into **rings** (pilot and production) with tag-based dynamic scopes
- Add **pre/post maintenance tasks**: VM snapshot before the window, service health check after
- Build an **Azure Monitor alert** or Resource Graph dashboard for VMs with missing Critical/Security updates
- Send Update Manager results to **Splunk** from my SIEM lab, or open a **ServiceNow** change for each maintenance window
- Bring the Lab 1 file server under the same schedule, so the whole series is patched and access-controlled

---

**Status: complete.** Fixed a guide whose schedule could never patch and whose validation could never pass → deployed a three-server domain with Terraform, working around a sold-out VM size → found fresh VMs were already compliant and rebuilt from a July image → assessment FAIL (2 missing security updates per server) → patched member servers first, DC last → re-assessment ALL PASS → scheduled window ran on its own.

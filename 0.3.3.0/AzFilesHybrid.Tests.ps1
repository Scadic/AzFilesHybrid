# Load definitions without module initialization, dependency imports, or network access.
$modulePath = Join-Path $PSScriptRoot 'AzFilesHybrid.psm1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count)
{
    throw ($parseErrors.Message -join [Environment]::NewLine)
}

if (-not ('Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount' -as [type]))
{
    Add-Type -TypeDefinition @'
namespace Microsoft.Azure.Commands.Management.Storage.Models
{
    public class PSStorageAccount
    {
        public string StorageAccountName { get; set; }
        public string ResourceGroupName { get; set; }
        public object AzureFilesIdentityBasedAuth { get; set; }
    }
}
'@
}

if (-not ('Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork' -as [type]))
{
    Add-Type -TypeDefinition @'
namespace Microsoft.Azure.Commands.Network.Models
{
    public class PSVirtualNetwork
    {
        public string Name { get; set; }
        public string ResourceGroupName { get; set; }
        public object[] Subnets { get; set; }
    }
    public class PSSubnet
    {
        public string Name { get; set; }
        public string Id { get; set; }
    }
}
'@
}

$definitions = $ast.EndBlock.Statements |
    Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -or $_ -is [System.Management.Automation.Language.TypeDefinitionAst] } |
    ForEach-Object { $_.Extent.Text }
$source = @'
using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Text
using namespace System.Security
'@ + [Environment]::NewLine + ($definitions -join [Environment]::NewLine)
. ([scriptblock]::Create($source))

# Test-only command shapes let Pester mock absent AD/Azure cmdlets without loading them.
$commandShape = {
    [CmdletBinding()]
    param(
        $Server, $Credential, $Identity, $Current, $Filter, $Properties, $Instance,
        $Name, $NewName, $Path, $SamAccountName, $AccountPassword,
        $AllowReversiblePasswordEncryption, $PasswordNeverExpires, $Description,
        $ServicePrincipalNames, $Enabled, $UserPrincipalName, $KerberosEncryptionType,
        [switch]$Reset, $NewPassword, $ResourceGroupName, $AccountName, $StorageAccountName,
        $KeyName, $StorageAccount, $VirtualNetworkName
    )
    throw 'Unexpected external command in an isolated test.'
}
foreach ($name in @(
    'Get-ADDomain', 'Get-ADComputer', 'Get-ADUser', 'Get-ADObject',
    'Get-ADPrincipalGroupMembership', 'New-ADComputer', 'New-ADUser',
    'Set-ADComputer', 'Set-ADUser', 'Set-ADAccountPassword', 'Rename-ADObject',
    'Get-AzStorageAccount', 'New-AzStorageAccountKey', 'Set-AzStorageAccount',
    'Get-AzVirtualNetwork', 'New-AzResourceGroup', 'Get-AzResourceGroup',
    'Get-AzStorageFileServiceProperty'
))
{
    Set-Item -Path "Function:\$name" -Value $commandShape
}

$script:adCredential = [pscredential]::new('CONTOSO\DelegatedAdmin', (ConvertTo-SecureString 'test-only' -AsPlainText -Force))
$script:domainInfo = [pscustomobject]@{
    DNSRoot = 'contoso.com'
    NetBIOSName = 'CONTOSO'
    DistinguishedName = 'DC=contoso,DC=com'
    ObjectGUID = [guid]::NewGuid()
    DomainSID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3' }
    Forest = 'contoso.com'
    ParentDomain = $null
}
$script:storage = New-Object Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount
$script:storage.StorageAccountName = 'storageone'
$script:storage.ResourceGroupName = 'rg'
$script:storage.AzureFilesIdentityBasedAuth = [pscustomobject]@{
    DirectoryServiceOptions = 'AD'
    ActiveDirectoryProperties = [pscustomobject]@{
        DomainName = 'contoso.com'
        AzureStorageSid = 'S-1-5-21-1-2-3-1000'
    }
}
$script:adObject = [pscustomobject]@{
    Name = 'storageone'
    DistinguishedName = 'CN=storageone,OU=Storage,DC=contoso,DC=com'
    ObjectClass = 'computer'
    SamAccountName = 'storageone$'
    SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1000' }
}

function Get-TestException
{
    param([scriptblock]$Action)
    try
    {
        & $Action
    }
    catch
    {
        return $_.Exception
    }
    throw 'Expected the operation to throw.'
}

Describe 'Explicit AD connections' {
    BeforeEach {
        Mock Assert-IsWindows {}
        Mock Request-ADFeature {}
        Mock Get-IsDomainJoined { $false }
        Mock Get-ADDomain { $script:domainInfo }
    }

    It 'requires both connection parameters on an Entra-only machine' {
        { Get-ADConnectionParameters } | Should Throw 'both'
        { Get-ADConnectionParameters -ADServer 'dc01.contoso.com' } | Should Throw 'both'
        { Get-ADConnectionParameters -ADCredential $script:adCredential } | Should Throw 'both'
    }

    It 'preserves domain-joined implicit connection defaults' {
        Mock Get-IsDomainJoined { $true }
        $result = Get-ADConnectionParameters
        $result.Count | Should Be 0
        Assert-MockCalled Get-ADDomain -Times 0 -Exactly
    }

    It 'pins explicit connections and validates their domain' {
        $result = Get-ADConnectionParameters -Domain 'contoso.com' -ADServer 'dc01.contoso.com' -ADCredential $script:adCredential
        $result.Server | Should Be 'dc01.contoso.com'
        $result.Credential | Should Be $script:adCredential
        Assert-MockCalled Get-ADDomain -Times 1 -Exactly -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential
        }
        { Get-ADConnectionParameters -Domain 'other.com' -ADServer 'dc01.contoso.com' -ADCredential $script:adCredential } |
            Should Throw 'not requested domain'
    }

    It 'rejects empty public connection arguments and whitespace endpoints' {
        $exception = Get-TestException { Join-AzStorageAccount -ResourceGroupName rg -StorageAccountName storageone -ADServer '' -ErrorAction Stop }
        $exception.Message | Should Match 'ADServer'
        { Get-ADConnectionParameters -ADServer ' ' -ADCredential $script:adCredential } | Should Throw 'host name'
    }

    It 'rejects missing join domain or OU before Azure writes' {
        Mock Ensure-KerbKeyExists { throw 'Must not generate keys' }
        Mock Validate-StorageAccount { throw 'Must not reach Azure' }
        { Join-AzStorageAccount -ResourceGroupName rg -StorageAccountName storageone -ADServer dc01.contoso.com -ADCredential $script:adCredential } |
            Should Throw 'explicit destination OU'
        { Join-AzStorageAccount -ResourceGroupName rg -StorageAccountName storageone -Domain contoso.com -ADServer dc01.contoso.com -ADCredential $script:adCredential } |
            Should Throw 'explicit destination OU'
        Assert-MockCalled Ensure-KerbKeyExists -Times 0 -Exactly
        Assert-MockCalled Validate-StorageAccount -Times 0 -Exactly
    }

    It 'forwards credentials through join including its final password reset' {
        Mock Validate-StorageAccount { $script:storage }
        Mock Assert-IsUnconfiguredOrNativeAD {}
        Mock New-ADAccountForStorageAccount { @{ ADObjectName = 'storageone'; Domain = 'contoso.com' } }
        Mock Set-StorageAccountDomainProperties {}
        Mock Update-AzStorageAccountADObjectPassword {}
        Join-AzStorageAccount -ResourceGroupName rg -StorageAccountName storageone -Domain contoso.com `
            -OrganizationalUnitDistinguishedName 'OU=Storage,DC=contoso,DC=com' `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential -Confirm:$false
        Assert-MockCalled New-ADAccountForStorageAccount -Times 1 -Exactly -ParameterFilter {
            $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential -and
            $OrganizationalUnitDistinguishedName -eq 'OU=Storage,DC=contoso,DC=com'
        }
        Assert-MockCalled Set-StorageAccountDomainProperties -Times 1 -Exactly -ParameterFilter {
            $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential
        }
        Assert-MockCalled Update-AzStorageAccountADObjectPassword -Times 1 -Exactly -ParameterFilter {
            $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential -and $RotateToKerbKey -eq 'kerb2'
        }
    }

    It 'does not mutate resources during a join WhatIf' {
        Mock New-ADAccountForStorageAccount {}
        Mock Ensure-KerbKeyExists {}
        Join-AzStorageAccount -ResourceGroupName rg -StorageAccountName storageone -Domain contoso.com `
            -OrganizationalUnitDistinguishedName 'OU=Storage,DC=contoso,DC=com' `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential -WhatIf
        Assert-MockCalled New-ADAccountForStorageAccount -Times 0 -Exactly -Scope It
        Assert-MockCalled Ensure-KerbKeyExists -Times 0 -Exactly
    }
}

Describe 'AD object writes and password management' {
    BeforeEach {
        Mock Assert-IsWindows {}
        Mock Request-ADFeature {}
        Mock Get-IsDomainJoined { $false }
        Mock Get-ADDomain { $script:domainInfo }
        Mock Assert-IsSupportedDistinguishedName {}
        Mock Ensure-KerbKeyExists {}
        Mock Get-AzStorageAccountKerbKeys { @(
            [pscustomobject]@{ KeyName = 'kerb1'; Value = 'first-test-key' },
            [pscustomobject]@{ KeyName = 'kerb2'; Value = 'second-test-key' }
        ) }
        Mock Get-ServicePrincipalName { 'cifs/storageone.file.core.windows.net' }
        Mock Get-ADObject { [pscustomobject]@{ DistinguishedName = 'OU=Storage,DC=contoso,DC=com' } }
        Mock Get-ADComputer {}
        Mock Get-ADUser {}
        Mock New-ADComputer {}
        Mock New-ADUser {}
    }

    It 'uses the delegated connection for both supported account types' {
        foreach ($type in @('ComputerAccount', 'ServiceLogonAccount'))
        {
            $null = New-ADAccountForStorageAccount -ADObjectName storageone -StorageAccountName storageone `
                -ResourceGroupName rg -Domain contoso.com -ObjectType $type `
                -OrganizationalUnitDistinguishedName 'OU=Storage,DC=contoso,DC=com' `
                -ADServer dc01.contoso.com -ADCredential $script:adCredential
        }
        Assert-MockCalled New-ADComputer -Times 1 -Exactly -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential -and $Path -eq 'OU=Storage,DC=contoso,DC=com'
        }
        Assert-MockCalled New-ADUser -Times 1 -Exactly -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential -and $Path -eq 'OU=Storage,DC=contoso,DC=com'
        }
    }

    It 'validates the OU before generating any Kerberos keys' {
        Mock Get-ADObject { throw 'OU access denied' }
        { New-ADAccountForStorageAccount -ADObjectName storageone -StorageAccountName storageone `
            -ResourceGroupName rg -Domain contoso.com -OrganizationalUnitDistinguishedName 'OU=Storage,DC=contoso,DC=com' `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential } | Should Throw 'OU access denied'
        Assert-MockCalled Ensure-KerbKeyExists -Times 0 -Exactly -Scope It
    }

    It 'forwards overwrite and rename connection parameters' {
        $script:existing = [pscustomobject]@{
            Name = 'storageone'; DistinguishedName = $script:adObject.DistinguishedName
            AllowReversiblePasswordEncryption = $true; Description = ''; Enabled = $false
            KerberosEncryptionType = 'None'
        }
        Mock Get-ADComputer { $script:existing }
        Mock Set-ADComputer {}
        Mock Rename-ADObjectWithConfirmation {}
        $null = New-ADAccountForStorageAccount -ADObjectName storageone -StorageAccountName storageone `
            -ResourceGroupName rg -Domain contoso.com -OverwriteExistingADObject `
            -OrganizationalUnitDistinguishedName 'OU=Storage,DC=contoso,DC=com' `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential
        Assert-MockCalled Set-ADComputer -Times 1 -Exactly -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential
        }
        Assert-MockCalled Rename-ADObjectWithConfirmation -Times 1 -Exactly -ParameterFilter {
            $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential
        }
    }

    It 'uses storage identity passwords and the explicit LDAP endpoint for key checks' {
        Mock Validate-StorageAccount { $script:storage }
        Mock Get-AzStorageAccountADObject { $script:adObject }
        Mock Get-AzStorageAccountActiveDirectoryProperties { $script:storage.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties }
        Mock Test-ADStorageAccountPassword { $Password -eq 'first-test-key' }
        $result = @(Test-AzStorageAccountADObjectPasswordIsKerbKey -ResourceGroupName rg -StorageAccountName storageone `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential)
        $result.Count | Should Be 2
        $result[0].KeyMatches | Should Be $true
        $result[1].KeyMatches | Should Be $false
        Assert-MockCalled Test-ADStorageAccountPassword -Times 2 -Exactly -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $UserName -eq 'CONTOSO\storageone$' -and
            $Password -in @('first-test-key', 'second-test-key')
        }
    }

    It 'surfaces operational password-check errors instead of false matches' {
        Mock Validate-StorageAccount { $script:storage }
        Mock Get-AzStorageAccountADObject { $script:adObject }
        Mock Get-AzStorageAccountActiveDirectoryProperties { $script:storage.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties }
        Mock Test-ADStorageAccountPassword { throw 'LDAP unavailable' }
        { Test-AzStorageAccountADObjectPasswordIsKerbKey -ResourceGroupName rg -StorageAccountName storageone `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential } | Should Throw 'LDAP unavailable'
    }

    It 'pins password resets to the delegated connection' {
        Mock Get-AzStorageAccount { $script:storage }
        Mock Assert-IsNativeAD {}
        Mock Get-AzStorageAccountADObject { $script:adObject }
        Mock Set-ADAccountPassword {}
        Update-AzStorageAccountADObjectPassword -ResourceGroupName rg -StorageAccountName storageone `
            -RotateToKerbKey kerb2 -SkipKeyRegeneration -Force -ADServer dc01.contoso.com -ADCredential $script:adCredential
        Assert-MockCalled Set-ADAccountPassword -Times 1 -Exactly -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential -and $Reset
        }
    }

    It 'forwards explicit connections through automatic rotation' {
        Mock Assert-IsNativeAD {}
        Mock Test-AzStorageAccountADObjectPasswordIsKerbKey {
            [pscustomobject]@{ KerbKeyName = 'kerb1'; KeyMatches = $true }
        }
        Mock Update-AzStorageAccountADObjectPassword {}
        Invoke-AzStorageAccountADObjectPasswordRotation -StorageAccount $script:storage `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential -Confirm:$false
        Assert-MockCalled Update-AzStorageAccountADObjectPassword -Times 1 -Exactly -ParameterFilter {
            $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential -and $RotateToKerbKey -eq 'kerb2'
        }
    }

}

Describe 'AD pipeline lookup' {
    BeforeEach {
        Mock Assert-IsWindows {}
        Mock Request-ADFeature {}
    }

    It 'does not leak domain metadata between pipeline lookups' {
        Mock Get-IsDomainJoined { $true }
        Mock Get-ADObject { $script:adObject }
        Mock Get-ADComputer { $script:adObject }
        $other = New-Object Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount
        $other.StorageAccountName = 'storagetwo'
        $other.ResourceGroupName = 'rg'
        $other.AzureFilesIdentityBasedAuth = [pscustomobject]@{
            ActiveDirectoryProperties = [pscustomobject]@{ DomainName = 'other.com'; AzureStorageSid = 'S-1-5-21-4-5-6-1000' }
        }
        $result = @(@($script:storage, $other) | Get-AzStorageAccountADObject)
        $result.Count | Should Be 2
        Assert-MockCalled Get-ADObject -Times 1 -Exactly -ParameterFilter { $Server -eq 'contoso.com' }
        Assert-MockCalled Get-ADObject -Times 1 -Exactly -ParameterFilter { $Server -eq 'other.com' }
    }

    It 'uses the selected DC and credentials for SID lookup and typed object retrieval' {
        Mock Get-IsDomainJoined { $false }
        Mock Get-ADDomain { $script:domainInfo }
        Mock Get-ADObject { $script:adObject }
        Mock Get-ADComputer { $script:adObject }
        $result = Get-AzStorageAccountADObject -StorageAccount $script:storage `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential
        $result.SamAccountName | Should Be 'storageone$'
        Assert-MockCalled Get-ADObject -Times 1 -Exactly -Scope It -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential
        }
        Assert-MockCalled Get-ADComputer -Times 1 -Exactly -Scope It -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential
        }
    }
}

Describe 'Legacy domain-joined account creation' {
    BeforeEach {
        Mock Assert-IsWindows {}
        Mock Request-ADFeature {}
        Mock Get-IsDomainJoined { $true }
        Mock Get-ADDomain { $script:domainInfo }
        Mock Get-ADComputer {
            if ($Identity)
            {
                [pscustomobject]@{ DistinguishedName = 'CN=client,OU=Storage,DC=contoso,DC=com' }
            }
        }
        Mock Get-ADUser {}
        Mock Get-ADObject { [pscustomobject]@{ DistinguishedName = 'OU=Storage,DC=contoso,DC=com' } }
        Mock Ensure-KerbKeyExists {}
        Mock Get-AzStorageAccountKerbKeys { [pscustomobject]@{ KeyName = 'kerb1'; Value = 'test-key' } }
        Mock Get-ServicePrincipalName { 'cifs/storageone.file.core.windows.net' }
        Mock New-ADComputer {}
    }

    It 'still discovers the local computer domain and parent container without explicit parameters' {
        $null = New-ADAccountForStorageAccount -ADObjectName storageone -StorageAccountName storageone -ResourceGroupName rg
        Assert-MockCalled Get-ADDomain -Times 1 -Exactly -Scope It -ParameterFilter { $Current -eq 'LocalComputer' }
        Assert-MockCalled New-ADComputer -Times 1 -Exactly -Scope It -ParameterFilter {
            $Server -eq 'contoso.com' -and $null -eq $Credential -and $Path -eq 'OU=Storage,DC=contoso,DC=com'
        }
    }
}

Describe 'AES256 workflow' {
    BeforeEach {
        Mock Assert-IsWindows {}
        Mock Request-ADFeature {}
        Mock Get-IsDomainJoined { $false }
        Mock Get-ADDomain { $script:domainInfo }
        Mock Assert-IsNativeAD {}
        Mock Assert-IsSupportedDistinguishedName {}
        Mock Get-AzStorageAccountADObject { $script:adObject }
        Mock Get-AzStorageAccountActiveDirectoryProperties { $script:storage.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties }
        Mock Set-ADComputer {}
        Mock Set-StorageAccountDomainProperties {}
        Mock Update-AzStorageAccountADObjectPassword {}
    }

    It 'forwards credentials to the attribute update, metadata lookup and password reset' {
        Update-AzStorageAccountAuthForAES256 -StorageAccount $script:storage -ADServer dc01.contoso.com `
            -ADCredential $script:adCredential -Confirm:$false
        Assert-MockCalled Set-ADComputer -Times 1 -Exactly -Scope It -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential -and $KerberosEncryptionType -eq 'AES256'
        }
        Assert-MockCalled Set-StorageAccountDomainProperties -Times 1 -Exactly -Scope It -ParameterFilter {
            $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential
        }
        Assert-MockCalled Update-AzStorageAccountADObjectPassword -Times 1 -Exactly -Scope It -ParameterFilter {
            $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential
        }
    }

    It 'does not change attributes or passwords under WhatIf' {
        Update-AzStorageAccountAuthForAES256 -StorageAccount $script:storage -ADServer dc01.contoso.com `
            -ADCredential $script:adCredential -WhatIf
        Assert-MockCalled Set-ADComputer -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-StorageAccountDomainProperties -Times 0 -Exactly -Scope It
        Assert-MockCalled Update-AzStorageAccountADObjectPassword -Times 0 -Exactly -Scope It
    }
}

Describe 'Explicit password binds' {
    BeforeEach {
        Add-Type -AssemblyName System.DirectoryServices.Protocols
        if (-not ('AzFilesHybridTests.LdapConnection' -as [type]))
        {
            Add-Type -TypeDefinition @'
namespace AzFilesHybridTests
{
    public class Options
    {
        public bool Signing { get; set; }
        public bool Sealing { get; set; }
    }
    public class LdapConnection
    {
        public object AuthType { get; set; }
        public object Credential { get; set; }
        public Options SessionOptions { get; set; }
        public bool Disposed { get; set; }
        public System.Exception Failure { get; set; }
        public LdapConnection()
        {
            SessionOptions = new Options();
        }
        public void Bind()
        {
            if (Failure != null)
            {
                throw Failure;
            }
        }
        public void Dispose()
        {
            Disposed = true;
        }
    }
}
'@
        }
        $script:ldapConnection = [AzFilesHybridTests.LdapConnection]::new()
        Mock New-Object { $script:ldapConnection } -ParameterFilter {
            $TypeName -eq 'System.DirectoryServices.Protocols.LdapConnection'
        }
    }

    It 'uses the selected endpoint, protects the bind and disposes a successful connection' {
        Test-ADStorageAccountPassword -Server dc01.contoso.com -UserName 'CONTOSO\storageone$' -Password 'test-key' |
            Should Be $true
        $script:ldapConnection.SessionOptions.Signing | Should Be $true
        $script:ldapConnection.SessionOptions.Sealing | Should Be $true
        $script:ldapConnection.Credential.UserName | Should Be 'CONTOSO\storageone$'
        $script:ldapConnection.Disposed | Should Be $true
        Assert-MockCalled New-Object -Times 1 -Exactly -Scope It -ParameterFilter {
            $TypeName -eq 'System.DirectoryServices.Protocols.LdapConnection' -and $ArgumentList[0] -eq 'dc01.contoso.com'
        }
    }

    It 'returns false only for an AD bad-password substatus and disposes the connection' {
        $script:ldapConnection.Failure = [System.DirectoryServices.Protocols.LdapException]::new(49, 'Invalid credentials', 'AcceptSecurityContext error, data 52e, v3839')
        Test-ADStorageAccountPassword -Server dc01.contoso.com -UserName 'CONTOSO\storageone$' -Password 'wrong-key' |
            Should Be $false
        $script:ldapConnection.Disposed | Should Be $true
    }

    It 'does not hide server failures or account restrictions as password mismatches' {
        foreach ($failure in @(
            [System.DirectoryServices.Protocols.LdapException]::new(81, 'Server unavailable'),
            [System.DirectoryServices.Protocols.LdapException]::new(49, 'Account disabled', 'AcceptSecurityContext error, data 533, v3839')
        ))
        {
            $script:ldapConnection.Failure = $failure
            $script:ldapConnection.Disposed = $false
            $exception = Get-TestException { Test-ADStorageAccountPassword -Server dc01.contoso.com -UserName 'CONTOSO\storageone$' -Password 'test-key' }
            $exception.Message | Should Match $failure.Message
            $script:ldapConnection.Disposed | Should Be $true
        }
    }
}

Describe 'DNS directory discovery' {
    BeforeEach {
        Mock Assert-IsWindows {}
        Mock Request-ADFeature {}
        Mock Get-IsDomainJoined { $false }
        Mock Get-ADDomain { $script:domainInfo }
        Mock Resolve-DnsNameInternal { [pscustomobject]@{ Type = 'A'; IPAddress = '192.0.2.1' } }
    }

    It 'queries forwarding domains with delegated credentials' {
        $result = New-AzDnsForwardingRuleSet -OnPremDomainName contoso.com -SkipParentDomain `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential
        $result.DnsForwardingRules.Count | Should Be 1
        Assert-MockCalled Get-ADDomain -Times 2 -Exactly -Scope It -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential
        }
    }

    It 'does not fall back implicitly when parent discovery needs a different domain server' {
        Mock Get-ADDomain {
            [pscustomobject]@{ DNSRoot = 'child.contoso.com'; NetBIOSName = 'CHILD'; ParentDomain = 'contoso.com' }
        }
        { New-AzDnsForwardingRuleSet -OnPremDomainName child.contoso.com `
            -ADServer dc01.child.contoso.com -ADCredential $script:adCredential } | Should Throw 'not requested domain'
        Assert-MockCalled Get-ADDomain -Times 0 -Exactly -Scope It -ParameterFilter { $Server -ne 'dc01.child.contoso.com' }
    }

    It 'uses delegated credentials for preflight computer-name discovery' {
        Mock Get-ADDomain { $script:domainInfo }
        Mock Assert-DnsForwarderArmTemplateVersion {}
        Mock Get-AzVirtualNetwork {
            $vnet = New-Object Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork
            $vnet.Name = 'vnet'
            $vnet.ResourceGroupName = 'rg'
            $subnet = New-Object Microsoft.Azure.Commands.Network.Models.PSSubnet
            $subnet.Name = 'subnet'
            $vnet.Subnets = @($subnet)
            $vnet
        }
        Mock Get-ADComputer {}
        $result = Confirm-AzDnsForwarderPreReqs -VirtualNetworkResourceGroupName rg -VirtualNetworkName vnet `
            -VirtualNetworkSubnetName subnet -DomainToJoin contoso.com -ADServer dc01.contoso.com -ADCredential $script:adCredential
        $result.DomainToJoin | Should Be 'contoso.com'
        Assert-MockCalled Get-ADComputer -Times 1 -Exactly -Scope It -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential
        }
    }
}

Describe 'AD queries versus local session operations' {
    BeforeEach {
        Mock Assert-IsWindows {}
        Mock Request-ADFeature {}
        Mock Get-IsDomainJoined { $false }
        Mock Get-ADDomain { $script:domainInfo }
    }

    It 'requires a diagnostic user instead of assuming the delegated admin' {
        Mock Get-ADUser {}
        { Get-OnPremAdUser -ADServer dc01.contoso.com -ADCredential $script:adCredential } | Should Throw 'UserName'
        Assert-MockCalled Get-ADUser -Times 0 -Exactly
    }

    It 'queries the supplied diagnostic user with delegated credentials' {
        Mock Get-ADUser { [pscustomobject]@{ Name = 'Alice' } }
        $null = Get-OnPremAdUser -Identity Alice -ADServer dc01.contoso.com -ADCredential $script:adCredential
        Assert-MockCalled Get-ADUser -Times 1 -Exactly -ParameterFilter {
            $Identity -eq 'Alice' -and $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential
        }
    }

    It 'keeps the domain-membership diagnostic failed on an Entra-only client' {
        Mock Write-Host {}
        Mock Format-Table {}
        $diagnosticErrors = @()
        Debug-AzStorageAccountADDSAuth -ResourceGroupName rg -StorageAccountName storageone -Filter '^CheckDomainJoined$' `
            -ADServer dc01.contoso.com -ADCredential $script:adCredential -ErrorAction SilentlyContinue -ErrorVariable diagnosticErrors
        ($diagnosticErrors | Out-String) | Should Match 'Machine is not domain-joined'
    }

    It 'reports the file-access diagnostic limitation instead of impersonating the delegated admin' {
        Mock Write-Host {}
        Mock Format-Table {}
        Mock Get-Acl { throw 'Must not inspect ACLs under a substituted identity' }
        $diagnosticErrors = @()
        Debug-AzStorageAccountADDSAuth -ResourceGroupName rg -StorageAccountName storageone -Filter '^CheckUserFileAccess$' `
            -UserName Alice -FilePath 'C:\test-file' -ADServer dc01.contoso.com -ADCredential $script:adCredential `
            -ErrorAction SilentlyContinue -ErrorVariable diagnosticErrors
        ($diagnosticErrors | Out-String) | Should Match 'requires a domain-joined Windows context'
        Assert-MockCalled Get-Acl -Times 0 -Exactly -Scope It
    }

    It 'rejects cross-domain and unqualified migration identities' {
        Mock Get-ADObject {}
        { Resolve-ADAccountSid -AccountName 'OTHER\Alice' -ADServer dc01.contoso.com -ADCredential $script:adCredential } |
            Should Throw 'not qualified'
        { Resolve-ADAccountSid -AccountName Alice -ADServer dc01.contoso.com -ADCredential $script:adCredential } |
            Should Throw 'domain-qualified'
        Assert-MockCalled Get-ADObject -Times 0 -Exactly
    }

    It 'resolves a domain-qualified security principal with the delegated connection' {
        Mock Get-ADObject { [pscustomobject]@{ objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1000') } }
        $result = Resolve-ADAccountSid -AccountName 'CONTOSO\Alice' -ADServer dc01.contoso.com -ADCredential $script:adCredential
        $result.Value | Should Be 'S-1-5-21-1-2-3-1000'
        Assert-MockCalled Get-ADObject -Times 1 -Exactly -ParameterFilter {
            $Server -eq 'dc01.contoso.com' -and $Credential -eq $script:adCredential -and $Filter -eq "sAMAccountName -eq 'Alice'"
        }
    }

    It 'preserves local well-known identity resolution without querying AD' {
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $account = $sid.Translate([System.Security.Principal.NTAccount]).Value
        $result = Resolve-ADAccountSid -AccountName $account -ADServer dc01.contoso.com -ADCredential $script:adCredential
        $result.Value | Should Be 'S-1-5-18'
        Assert-MockCalled Get-ADDomain -Times 0 -Exactly -Scope It
    }

    It 'rejects offline provisioning before native or Azure operations' {
        Mock Register-OfflineMachineWindows { throw 'Must not run djoin' }
        Mock Get-AzResourceGroup { throw 'Must not reach Azure' }
        { Register-OfflineMachine -MachineName dnsone -Domain contoso.com } | Should Throw 'Offline machine provisioning'
        { Join-AzDnsForwarder -DomainToJoin contoso.com -DnsForwarderNames dnsone -Confirm:$false } | Should Throw 'Offline machine provisioning'
        { New-AzDnsForwarder -DnsForwardingRuleSet ([DnsForwardingRuleSet]::new()) `
            -VirtualNetworkResourceGroupName rg -VirtualNetworkName vnet -VirtualNetworkSubnetName subnet } |
            Should Throw 'Offline machine provisioning'
        Assert-MockCalled Register-OfflineMachineWindows -Times 0 -Exactly
        Assert-MockCalled Get-AzResourceGroup -Times 0 -Exactly
    }

    It 'retains domain-joined offline provisioning routing' {
        Mock Get-IsDomainJoined { $true }
        Mock Get-ADComputerInternal {}
        Mock Register-OfflineMachineWindows { 'test-blob' }
        Register-OfflineMachine -MachineName dnsone -Domain contoso.com | Should Be 'test-blob'
        Assert-MockCalled Register-OfflineMachineWindows -Times 1 -Exactly
    }
}

Describe 'Diagnostic dispatcher connection forwarding' {
    It 'forwards diagnostic AD credentials without substituting the target user' {
        Mock Get-AzStorageAccount { $script:storage }
        Mock Debug-AzStorageAccountADDSAuth {}
        Debug-AzStorageAccountAuth -ResourceGroupName rg -StorageAccountName storageone -Filter CheckADObject `
            -UserName Alice -ADServer dc01.contoso.com -ADCredential $script:adCredential
        Assert-MockCalled Debug-AzStorageAccountADDSAuth -Times 1 -Exactly -Scope It -ParameterFilter {
            $UserName -eq 'Alice' -and $ADServer -eq 'dc01.contoso.com' -and $ADCredential -eq $script:adCredential
        }
    }
}

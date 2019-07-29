function New-DBStorageConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccount,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [String]$ServerName,
        [Parameter(Mandatory = $false)]
        [String]$AzureFirewallName = "AzureWebAppFirewall",
        [Parameter(Mandatory = $true)]
        [String]$Environment,
        [Parameter(Mandatory = $true)]
        [String]$KeyVaultName,
        [Parameter(Mandatory = $true)]
        [String]$KeyVaultSecretName,
        [Parameter(Mandatory = $true)]
        [String]$DataBaseName,
        [Parameter(Mandatory = $true)]
        [String]$ContinerName
    )

    $policyName = "$($ContinerName)Datamngmt"
    $context =  (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccount).context
    Set-AzStorageContainerStoredAccessPolicy -Policy $policyName -Container $ContinerName -Permission "rl" -Context $context -NoExpiryTime
    $sasToken = (New-AzStorageBlobSASToken -Policy $policyName -Container $ContinerName -ExpiryTime "9999-12-31T23:59Z" -Context $context  )

    #$sasToken = (New-AzStorageAccountSASToken -Service Blob, Table -ResourceType Container, Object -Permission "lr" -ExpiryTime "9999-12-31T23:59Z" -Context $context).Trim("?")


    try {
        $AgentIP = (Invoke-WebRequest ifconfig.me/ip -UseBasicParsing).Content.Trim()
        $ServerFQDN = "$ServerName.database.windows.net"

        # --- Retrieve SQL Server details
        Write-Verbose -Message "Searching for server resource $($ServerName)"
        $ServerResource = Get-AzResource -Name $ServerName -ResourceType "Microsoft.Sql/servers"
        if (!$ServerResource) {
            throw "Could not find SQL server with name $ServerName"
        }

        Write-Verbose -Message "Retrieving server login details"
        $SqlServerUserName = (Get-AzSqlServer  -ResourceGroupName $ServerResource.ResourceGroupName -ServerName $ServerName).SqlAdministratorLogin

        Write-Verbose -Message "Retrieving secure server password"
        $SqlServerPassword = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName).SecretValueText
        if (!$SqlServerPassword) {
            throw "Could not retrieve secure password for $ServerName"
        }
        $CredentialName = "$($StorageAccount)RCred"
        $DataSourceName = "$($StorageAccount)StorConnection"
        # --- Add agent IP exception to the firewall
        Write-Verbose -Message "Updating firewall rule with agent ip: $AgentIP"
        $FirewallUpdateParameters = @{
            StartIPAddress    = $AgentIp
            EndIPAddress      = $AgentIp
            FirewallRuleName  = $AzureFirewallName
            ServerName        = $ServerName
            ResourceGroupName = $ServerResource.ResourceGroupName
        }

        if (!(Get-AzSqlServerFirewallRule -ServerName $ServerName -ResourceGroupName $ServerResource.ResourceGroupName -FirewallRuleName $AzureFirewallName -ErrorAction SilentlyContinue)) {
            $null = New-AzSqlServerFirewallRule @FirewallUpdateParameters
        }
        else {
            $null = Set-AzSqlServerFirewallRule @FirewallUpdateParameters
        }

        $Q1 = @"
        CREATE DATABASE SCOPED CREDENTIAL $CredentialName
        WITH IDENTITY = 'SHARED ACCESS SIGNATURE',
        SECRET = '$sasToken'
"@
    $SQLCmdParameters = @{
        ServerInstance  = $ServerFQDN
        Database        = $DataBaseName
        Username        = $SqlServerUserName
        Password        = $SqlServerPassword
        OutputSqlErrors = $true
        Query           = $Q1
    }
    Invoke-Sqlcmd @SQLCmdParameters

        $Q2 = @"
        CREATE EXTERNAL DATA SOURCE $DataSourceName
        WITH ( TYPE = BLOB_STORAGE,
        LOCATION = 'https://$StorageAccount.blob.core.windows.net',
        CREDENTIAL= $CredentialName);
"@
    $SQLCmdParameters = @{
        ServerInstance  = $ServerFQDN
        Database        = $DataBaseName
        Username        = $SqlServerUserName
        Password        = $SqlServerPassword
        OutputSqlErrors = $true
        Query           = $Q2
    }
    Invoke-Sqlcmd @SQLCmdParameters
    }
    catch {
        throw "$_"
    }
    finally {
        $ServerResource = Get-AzResource -Name $ServerName -ResourceType "Microsoft.Sql/servers"
        if ((Get-AzSqlServerFirewallRule -ServerName $ServerName -ResourceGroupName $ServerResource.ResourceGroupName -FirewallRuleName $AzureFirewallName -ErrorAction SilentlyContinue)) {
            $null = Remove-AzSqlServerFirewallRule -FirewallRuleName $AzureFirewallName -ServerName $ServerName -ResourceGroupName $ServerResource.ResourceGroupName
        }
    }
}

<#
.Synopsis
   Identify Virtual Machines with Mounted CDRoms
.DESCRIPTION
   Identify Virtual Machines that have Mounted CDRoms either an ISO or
   the physical drive of the server host. 
.EXAMPLE
   Check all VMs on connected servers

   Get-VM | Get-MountedCDRom

.EXAMPLE
   Check only VMs whos name matches the name or wildard shown

   Get-MountedCDRom -VMName win*
#>
function Get-VMMountedCDRom
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Virtual Machine Object
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0,
                   ParameterSetName="VMOject")]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl[]]
        $VM
    )

    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }

        if(!($VM))
        {
            $VM = Get-VM
        }
    }
    Process
    { 
        foreach ($virtualmachine in $VM)
        {
            $virtualmachine | Select-Object Name, @{Label="ISO file"; Expression = { ($_ | Get-CDDrive).ISOPath }}
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Shows number of console connections
.DESCRIPTION
   Shows number of console connections for a given VM.
.EXAMPLE
   Get only VM's with active connections

   Get-VM | Get-VMConsoleConnectionCount | where {$_.Connections -ne 0}

#>
function Get-VMConsoleConnectionCount
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Virtual Machine Object
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0,
                   ParameterSetName="VMOject")]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl[]]
        $VM
    )

    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }

        if(!($VM))
        {
            $VM = Get-VM
        }
    }
    Process
    {
        foreach ($virtualmachine in $VM)
        {
            Get-View -VIObject $virtualmachine -Property Name,Runtime.NumMksConnections | Select-Object Name,@{n="Connections"; e={$_.Runtime.NumMksConnections}}
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Check virtual Machine Tool status
.DESCRIPTION
   Ceck a given list of VMs or all VMs in a connected VMware Infrastucture for their tool status
.EXAMPLE
   Get the tool status for all VMs 

   PS C:\> Get-VMToolStatus


.EXAMPLE
   Get tool status for a filtered list of VMs in the infrastructure.

   PS C:\> get-vm ALB-* | Get-VMToolStatus
#>
function Get-VMToolStatus
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl[]]
        $VM
    )

    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }

        if(!($VM))
        {
            $VM = Get-VM
        }
    }
    Process
    {
        foreach ($virtualmachine in $VM)
        {
            $virtualmachine | Select-Object Name,@{n="ToolStatus"; e={$_.ExtensionData.Guest.ToolsStatus}}
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Find a VM by MAC Address
.DESCRIPTION
   Finds a VM and Networking information given its MAC Address.
.EXAMPLE
   Finds the VM with the given MAC Address

   PS C:\> Get-VM | Search-VMMacAddress -MAC 00:50:56:81:4a:0c


    VMName       : win2k8_vuln
    VMHost       : 192.168.1.143
    AddapterName : Network adapter 1
    NetworkName  : VM Network
    MacAddress   : 00:50:56:81:4a:0c

#>
function Search-VMMacAddress
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Single Virtual Machine Object or collection.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl[]]
        $VM,


        # MAC Address to seach for.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=0)]
        [string]$MAC
    )

    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }
    }
    Process
    {    
        $Found = $False
        foreach ($virtualmachine in $VM)
        {
            if ($Found){Break}
            Write-Verbose "Checking VM $($virtualmachine.Name)"
            Get-NetworkAdapter -VM $virtualmachine | ForEach-Object {
                if ($_.MacAddress -eq $MAC)
                {
                    $VMNetProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                    $VMNetProps.Add("VMName",$virtualmachine.Name)
                    $VMNetProps.Add("VMHost", $virtualmachine.VMHost)
                    $VMNetProps.Add("AddapterName",$_.Name)
                    $VMNetProps.Add("NetworkName",$_.NetworkName)
                    $VMNetProps.Add("MacAddress",$_.MacAddress)
                    New-Object -TypeName psobject -Property $VMNetProps
                    $Found = $true
                }
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Find a VM by IP Address
.DESCRIPTION
   Finds a Powered On VM given its IPv4 or IPv6 address.
.EXAMPLE
   Finds the VM with the given IP Address from a list of VM

   PS C:\> Get-VM ALB* | Search-VMIPAddress -IPAddress 192.168.10.12 -verbose

   VMName                                    VMHost                                    IPAddress                               
   ------                                    ------                                    ---------                               
   ALB-DC02                                  192.168.1.143                             192.168.10.12

.Example

   Searches thru all VMs for the one with IP one is looking for.

      PS C:\> Search-VMIPAddress -IPAddress 192.168.10.12 -verbose

   VMName                                    VMHost                                    IPAddress                               
   ------                                    ------                                    ---------                               
   ALB-DC02                                  192.168.1.143                             192.168.10.12

#>
function Search-VMIPAddress
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (

        # Virtual Machine Object to seach against
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl[]]
        $VM,

        # IP Address to seach for.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=0)]
        [string]$IPAddress
    )

    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }
    }
    Process
    {
        if (!$VM)
        {
            $VM = Get-VM
        }
        $Found = $False
        foreach ($virtualmachine in $VM)
        {
            if ($Found){Break}
            Write-Verbose "Checking VM $($virtualmachine.Name)"
            $virtualmachine.Guest.IPAddress | ForEach-Object {
                if ($_ -eq $IPAddress)
                {
                    $VMNetProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                    $VMNetProps.Add("VMName",$virtualmachine.Name)
                    $VMNetProps.Add("VMHost", $virtualmachine.VMHost)
                    $VMNetProps.Add("IPAddress",$_)
                    New-Object -TypeName psobject -Property $VMNetProps
                    $Found = $true
                }
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Finds Old Snapshots
.DESCRIPTION
   Finds Snapshots older than a given number of hous, days, moths or a date.
.EXAMPLE
   Finds snapshots older than 2 months

   PS C:\> get-vm | Search-VMOldSnapshots -Months 2
#>
function Search-VMOldSnapshots
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Single Virtual Machine Object or collection.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl[]]
        $VM,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Days")]
        [int]$Days,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Hours")]
        [int]$Hours,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Months")]
        [int]$Months,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Date")]
        [datetime]$Date
    )

    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }

        if(!($VM))
        {
            $VM = Get-VM
        }

        switch ($PsCmdlet.ParameterSetName)
        {
            "Hours"  {$comparedate = (Get-Date).AddHours(-$Hours)}
            "Days"   {$comparedate = (Get-Date).AddDays(-$Days)}
            "Months" {$comparedate = (Get-Date).AddMonths(-$Months)}
            "Date"   {$comparedate = $Date}
        }
    }
    Process
    {
        foreach ($VMachine in $VM)
        {
            $snapshots = Get-Snapshot -VM $VMachine
            
            foreach ( $snap in $snapshots )
            {
	            if ( $snap.Created -lt $comparedate ) 
                {
		            $snap
	            }
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Retrives specific types of event from a vCenter server
.DESCRIPTION
   Retrives events for VM creation, deletion or console access from a vCenter server
.EXAMPLE
   Find all events for console access in the last 2 days for a VM Named VM1

   Get-VMEvents -Days 2 -VMName vm1 -EventType Console

.EXAMPLE
   Find all event creation events in the last month.

   Get-VMEvents -Months 1 -EventType Creatio
#>
function Get-VMEvents
{ 
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Single Virtual Machine Object or collection.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [string]
        $VMName,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Days")]
        [int]$Days,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Hours")]
        [int]$Hours,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Months")]
        [int]$Months,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1,
                   ParameterSetName="Date")]
        [datetime]$Date,

        [ValidateSet("Creation","Deletion","Console","Any")] 
        $EventType
    )

    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }

        switch ($PsCmdlet.ParameterSetName)
        {
            "Hours"  {$startdate = (Get-Date).AddHours(-$Hours)}
            "Days"   {$startdate = (Get-Date).AddDays(-$Days)}
            "Months" {$startdate = (Get-Date).AddMonths(-$Months)}
            "Date"   {$startdate = $Date}
        }

        switch ($EventType)
        {
            "Console"  {$Types = "VmConnectedEvent", "VmAcquiredTicketEvent"}
            "Deletion"   {$Types = "VMRemovedEvent"}
            "Creation" {$Types = "VmCreatedEvent","VmDeployedEvent","VmClonedEvent","VmDiscoveredEvent","VmRegisteredEvent"}
        }

        $eventnumber = 1000
    }
    Process
    {
        $report = @()
        $ServiceInstance = get-view ServiceInstance
        $EventManager = Get-View eventManager
        $EventFilterSpec = New-Object VMware.Vim.EventFilterSpec
        $EventFilterSpec.time = New-Object VMware.Vim.EventFilterSpecByTime
        $EventFilterSpec.time.beginTime = $startdate
        $EventFilterSpec.time.endtime = (Get-Date)
        $EventFilterSpec.Type = $Types
        if ($VMName)
        {
            $vmentity = get-vm -Name $VMName | get-view 
            $EventFilterSpec.Entity = New-Object VMware.Vim.EventFilterSpecByEntity
            $EventFilterSpec.Entity.Entity = $vmentity.moref
        }
        $ecollectionImpl = Get-View ($EventManager.CreateCollectorForEvents($EventFilterSpec))
        $ecollection = $ecollectionImpl.ReadNextEvents($eventnumber) 
        
	        foreach($event in $ecollection)
            {
                $report += $event
            }
        
        $report

    }
    End
    {
    }
}


<#
.Synopsis
   List all current sessions.
.DESCRIPTION
   List all sessions on the current connected vCenter or ESX/ESXi server.
.EXAMPLE
   Get all current sessions.

   PS C:\> Get-VIMSessions
#>
function Get-VIMSessions
{
    Begin
    {
        # Make sure PowerCLI is installed and loaded
        if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
        {
            Add-PsSnapin VMware.VimAutomation.Core
        }
    }

    Process
    {
        $SessionMgr = Get-View $DefaultViserver.ExtensionData.Client.ServiceContent.SessionManager
        $AllSessions = @()
        
        Foreach ($session in $SessionMgr.SessionList) 
        {
            # Identify is the session is the current one
            If ($session.Key -eq $SessionMgr.CurrentSession.Key) 
            {
            $SessionStatus = "Current Session"
            } 
            Else 
            {
            $SessionStatus = "Idle"
            }
        
            $SessionProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
            $SessionProps.Add("UserName", $session.username)
            $SessionProps.add("FullName", $session.FullName)
            $SessionProps.Add("Status",$SessionStatus)
            $SessionProps.add("Key",$session.key)
            $SessionProps.Add("LoginTime", ($session.LoginTime).ToLocalTime())
            $SessionProps.Add("LastActiveTime",($session.LastActiveTime).ToLocalTime())

            New-Object -TypeName PSObject -Property $SessionProps
        }
    }
    End
    {
    }
}
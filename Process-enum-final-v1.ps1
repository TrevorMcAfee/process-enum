param([string]$computer=$null,[int]$p=$null,[switch]$tree,[int]$search=$null,[string]$filepath=$null,$cred,[switch]$table=$null,[switch]$list=$null,$outpath=$null,[switch]$vt=$null,[switch]$h=$null,[switch]$help=$null,[switch]$raw=$null)

$vtsleep = 15
$vtAPIKey = "" #Add your API key here


if($h -or $help)
{
    $command = $MyInvocation.MyCommand

    write-host @"

    Usage: $command [options]

    When executed without options, will display a list of all running processes as a flat list.

    When executed given a PID or Filepath, will search the file system for the process' lineage, loaded DLLs, Netstat results,
    scheduled tasks, services, Autostart Registry and folder matches, and file timestamps. Additional Data can be retrieved with more options.
    
    Main Options:

    <no option>            Displays all running processes as a flat list. Not compatible with search, -p, filepath, or vt.
    -tree                  Display All running processes in tree format. Not compatible with search, -p, filepath, or vt. Defaults to Table output format
    -p [PID]               Process ID to get information for. Not compatible with -filepath. Takes precendence over -filepath.
    -filepath [filename]   Find information related to [filename]. If running as a process, get process information as well. Not Compatible with -p.
    
    Additional Options:
    -computer              Computer Name or IP address to run this script against
    -cred [var]            Supply your own Get-Credential variable for the script to use when accessing remote systems
    -search [min]          Search the filesystem for other files created within [min] minutes of the file or executable in quetsion
    -vt                    Check Non-Microsoft DLLs against VirusTotal. Valid API key must be set within script.
                           VirusTotal lookups will always be done from the local system, even if script is executed against a remote machine.
    -h                     Display this Help message
    -help                  Display this help message

    Output Format Options:
    -table                 Display results in Format-Table format. Not Compatible with -list option
    -list                  Display results in Format-List format. Not compatible with -tree option. This is the default option if none other specified.
    -outpath [path]        Save each type of result as separate CSV file in [path]
    -raw                   Output results without formatting. Use this if you want to save to your own variable to use or parse separately. 
    
    Usage Examples:
    $command
    $command -tree
    $command -p 1492
    $command -p 1492 -search 5 -vt 
    $command -filepath "C:\windows\system32\svchost.exe" -table
    $command -computer 192.168.1.10 -p 2468 -vt -search 5 -table -outpath "C:\temp\"

"@

    exit
}

#check if given the outpath variable, and if so, append a slash to the end if the path given doesn't end with one.
if($outpath)
{
    if($outpath[-1] -ne "\")
    {
        $outpath += "\"
    }
}

#This function encompassases all of the checks to be run regardless of option. This is wrapped in a function so that it
# can easily be executed against a remote machine with the invoke-command function.
Function FullScript($p, $tree, $search, $filepath)
{

$global:process_Table = $null

#Expects Get-WmiObject win32_process formatted process
#Creating a custom table to hold the consolidated process information from multiple commands
Function CreateProcessTable($process)
{
    #if table doesn't already exist, create it. otherwise just add to it
    if(!$global:process_table)
    {
        # Creating custom table -- https://docs.microsoft.com/en-us/archive/blogs/rkramesh/creating-table-using-powershell
        $global:process_table = New-Object System.Data.DataTable "Processes"
        $global:process_table.Columns.Add((New-Object system.data.datacolumn Name,([string])))
        $global:process_table.Columns.Add((New-Object system.data.datacolumn PID,([int])))
        $global:process_table.Columns.Add((New-Object system.data.datacolumn PPID,([int])))
        $global:process_table.Columns.Add((New-Object system.data.datacolumn ProcessUser,([string])))
        $global:process_table.Columns.Add((New-Object system.data.datacolumn ExecutablePath,([string])))
        $global:process_table.Columns.Add((New-Object system.data.datacolumn CommandLine,([string])))
    }

    #add information to new process information table
    $row = $global:process_table.NewRow()
        
    $row.name = $process.indentedname
    $row.PID = $process.processId
    $row.PPID = $process.parentprocessid
    $row.ProcessUser = $process.Username               
    $row.ExecutablePath = $process.executablepath 
    $row.CommandLine = $process.commandline

    $global:process_table.rows.add($row)
    
}

Function GetTasklist()
{
    #get process info from tasklist to get user name data
    return (tasklist /v /fo csv | convertfrom-csv)
}


#found at https://social.technet.microsoft.com/Forums/windowsserver/en-US/87b5e231-4832-43ca-92ed-0ab70b6e6726/how-to-recursively-print-process-parent-process-grand-parent-process-great-grand-parent-process?forum=winserverpowershell
###STart technet code. adding my own along the way. look at process-tree-technet script to get original code

Function Show-ProcessTree
{
    $mytasklist = GetTasklist

    Function Get-ProcessChildren($P,$Depth=1)
    {
        $procs | Where-Object {$_.ParentProcessId -eq $p.ProcessID -and $_.ParentProcessId -ne 0} | ForEach-Object {
            
            $indentedname = "{0}|--{1}" -f (" "*3*$Depth),$_.Name
            $_ | Add-Member NoteProperty IndentedName $indentedname
            $thispid = $_.processid
            if(!$_.Username)
            {
                $_ | Add-Member NoteProperty Username  ($mytasklist | where-object {$_.PID -eq $thispid} | select -expand "User Name")
            }
            CreateProcessTable($_)
            Get-ProcessChildren $_ (++$Depth)
            $Depth--
        }
    }


    $filter = {-not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) -or $_.ParentProcessId -eq 0}
    $procs = Get-WmiObject Win32_Process
    $top = $procs | Where-Object $filter | Sort-Object ProcessID
    
    foreach ($p in $top)
    {

        $p | Add-Member NoteProperty IndentedName $p.name
        $p | Add-Member NoteProperty Username ($mytasklist | Where-Object {$_.PID -eq $p.processid} | select -expand "User Name")
        
        CreateProcessTable($p)
        
        Get-ProcessChildren $p
    }
}

##########END PROCESS TREE CODE FROM TECHNET


Function MyProcessList
{

    $mytasklist = GetTasklist
    
    $mywmi = gwmi win32_process

    foreach ($process in $mywmi)
    {
        $process | Add-Member NoteProperty Indentedname $process.name
        $process | Add-Member NoteProperty Username ($mytasklist | Where-Object {$_.PID -eq $process.processid} | select -expand "User Name")
        
        CreateProcessTable($process)
    }

}


#Powershell V2 compatible way to get scheduled tasks. 
Function GetTasks($process){
    $tasks = schtasks /query /fo csv /v | convertfrom-csv 

    if ($taskResult = $tasks | Where-Object {$_."Task to run" -like $process.executablepath + "*"} )
    {
        $taskResult
    }
}


Function SearchRegistry($process){

    $finalResult = @()
    
    $registryResults = @()
    foreach ($reg in $autostart_registry)
    {
        $temp = reg query $reg /s /f $process.executablepath 2> $null
        if ($temp -and $temp[-1] -notmatch " 0 match")
        {
            $registryResults += $temp[0..($temp.length-3)]
        }
    }

    #Convert the raw string output from reg.exe to a PowerShell Object with defined properties for the key it was found in and the value that was found
    for ($i = 1; $i -lt $registryResults.count; $i += 3)
{
    $ob = new-object psobject
    $ob | add-member -type NoteProperty -name "Key" -Value $registryResults[$i]
    $ob | Add-Member -type NoteProperty -name "Value" -Value $registryResults[$i+1].trim()
    $finalResult += $ob
}

    return $FinalResult
}

Function AutostartFolders($process)
{
    $results = @()
    
    #start with standard system startup folder
    $autostartFolders = @( "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")

    #Get users on system and add the start menu startup folder to the list of directories to search
    foreach($user in (gci "$env:SystemDrive\users"))
    {
        $autostartFolders += $user.fullname + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    
    #create an object we can use to find and search the target of shortcuts
    $sh = New-Object -ComObject wscript.shell

    foreach($folder in $autostartFolders)
    {
        $files = gci $folder -ErrorAction SilentlyContinue
        foreach ($file in $files)
        {

            if($file.fullname -eq $process.executablepath)
            {
                $results += $file.fullname
            }
            
            #If file is a shortcut, check the target to see if it's pointing to the executable in question
            if ($file.extension -eq ".lnk")
            {
                $target = $sh.createshortcut($file.fullname).targetpath 

                if ($target -eq $process.executablepath)
                {
                    $results += $file.fullname
                }
            }
        }
    }

    return $results
}

Function SearchFilesystem($process){
    $drives = gwmi win32_logicaldisk | Where-Object {$_.drivetype -eq 3} | select -expand deviceid
     $suspectExecutable = gci $process.executablepath -ErrorAction SilentlyContinue

     $results = @()

    if (!$suspectExecutable)
    {
       return
    }

    if (!$search)
    {
        return $suspectExecutable
    }

    if($search -gt 0)
    {
        foreach ($drive in $drives)
        {
            #note the added '\' to the gci command. this is required for the filesystem search will fail.
            $results += gci -recurse "$drive\" -ErrorAction SilentlyContinue | Where-Object {$_.creationtime -gt $suspectExecutable.creationtime.addminutes(-$search) -and $_.creationtime -lt $suspectExecutable.creationtime.addminutes($search)} | select creationtime, fullname 
        }
    }
    return $results
}

#All Registry autostart locations used by autorunsc64.exe (version 13.96 executed on windows 10)
$autostart_registry = @("HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute",
"HKLM\Software\Microsoft\Office\PowerPoint\Addins",
"HKLM\Software\Wow6432Node\Microsoft\Office\PowerPoint\Addins",
"HKLM\Software\Microsoft\Office\Word\Addins",
"HKLM\Software\Wow6432Node\Microsoft\Office\Word\Addins",
"HKLM\SOFTWARE\Classes\Htmlfile\Shell\Open\Command\(Default)",
"HKLM\System\CurrentControlSet\Services",
"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers",
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters",
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers",
"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GpExtensions",
"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors",
"HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers",
"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SecurityProviders",
"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages",
"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages",
"HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
"HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries",
"HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries",
"HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64",
"HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64",
"HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms",
"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VmApplet",
"HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls",
"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell",
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
"HKLM\SOFTWARE\Classes\Protocols\Filter",
"HKLM\SOFTWARE\Classes\Protocols\Handler",
"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
"HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\IconServiceLib",
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
"HKLM\Software\Classes\*\ShellEx\ContextMenuHandlers",
"HKLM\Software\Classes\Drive\ShellEx\ContextMenuHandlers",
"HKLM\Software\Classes\*\ShellEx\PropertySheetHandlers",
"HKLM\Software\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers",
"HKLM\Software\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers",
"HKLM\Software\Classes\Directory\ShellEx\ContextMenuHandlers",
"HKLM\Software\Classes\Directory\Shellex\DragDropHandlers",
"HKLM\Software\Classes\Directory\Shellex\PropertySheetHandlers",
"HKLM\Software\Classes\Directory\Shellex\CopyHookHandlers",
"HKLM\Software\Classes\Directory\Background\ShellEx\ContextMenuHandlers",
"HKLM\Software\Classes\Folder\ShellEx\ContextMenuHandlers",
"HKLM\Software\Classes\Folder\ShellEx\DragDropHandlers",
"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
"HKLM\Software\Microsoft\Internet Explorer\Extensions",
"HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions",
"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32",
"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32",
"HKLM\Software\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance",
"HKLM\Software\Wow6432Node\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance",
"HKLM\Software\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance",
"HKLM\Software\Wow6432Node\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance",
"HKCU\Control Panel\Desktop\Scrnsave.exe",
"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKCU\Software\Microsoft\Internet Explorer\UrlSearchHooks")



Function GetProcessLineage($process)
{
        #clearing process table variable to prevent conflicts from multiple runs based off file path
        Clear-Variable process_Table -scope Global

    do
    {
        $mytasklist = GetTasklist
        $ppid = $process.ParentProcessId
      
        $process | Add-Member NoteProperty IndentedName $process.name
        $process | Add-Member NoteProperty Username ($mytasklist | Where-Object {$_.PID -eq $process.processid} | select -expand "User Name")
        


        CreateProcessTable($process)

    }while($process = Get-WmiObject win32_process -Filter "processid=$ppid")
    
}


Function GetNetworkActivity($p)
{
    $results = @()

    #To make this script PowerShell v2.0 compatible, we need to use netstat and manually parse the output
    #instead of using the newer Get-NetTCPConnection and Get-NetUDPEndpoint Cmdlets
    $net = netstat -ano | select-string "\b$p$"
    if($net)
    {
        foreach ($line in $net)
        {
            $temp = $line -split '\s+'
        
            $ConnectionObject = New-Object -TypeName psobject
            $ConnectionObject | Add-Member -MemberType NoteProperty -Name PID $p
            $ConnectionObject | Add-Member -MemberType NoteProperty -Name Protocol $temp[1]

            #using substring to handle IPv6 Addresses
            $ConnectionObject | Add-Member -MemberType NoteProperty -Name LocalAddress $temp[2].substring(0, $temp[2].lastindexof(':'))  
            $ConnectionObject | Add-Member -MemberType NoteProperty -Name LocalPort $temp[2].split(':')[-1]
            
            if ($temp[1] -eq "TCP")
            {
                $ConnectionObject | Add-Member -MemberType NoteProperty -Name ForeignAddress $temp[3].substring(0, $temp[2].lastindexof(':'))  
                $ConnectionObject | Add-Member -MemberType NoteProperty -Name ForeignPort $temp[3].split(':')[-1]
                $ConnectionObject | Add-Member -MemberType NoteProperty -Name State $temp[4]
            }
            else
            {
                $ConnectionObject | Add-Member -MemberType NoteProperty -Name ForeignAddress $null 
                $ConnectionObject | Add-Member -MemberType NoteProperty -Name ForeignPort $null
                $ConnectionObject | Add-Member -MemberType NoteProperty -Name State $null
            }
        
            $results += $ConnectionObject
        
        }
    }
    return $results
}

Function GetFileTimestamps($process)
{
   
    return (gci $process.executablepath -ErrorAction SilentlyContinue | select Name, CreationTime, CreationTimeUtc, LastWriteTime, LastWriteTimeUtc, LastAccessTime, LastAccessTimeUtc)

}

Function GetService($process)
{
    $services = Get-WmiObject win32_service

    if ($ServiceResult = $Services | Where-Object {$_.Pathname -like "*" + $process.executablepath + "*"} )
    {
        return $ServiceResult 
    }

}

#expecting powershell's Get-Process process object
Function GetDLLs($gp_process)
{
    $LoadedDLLs = $gp_process | select -expand modules

    #get SHA256 hash of each DLL loaded into file using certutil. Replaces any spaces produced by certutil (common in older OSes)
    $LoadedDLLs | foreach {$_ | Add-Member NoteProperty Hash ((certutil -hashfile $_.filename SHA256)[1] -replace '\s','')  }
    return $LoadedDLLs
}

Function GetPersistenceInfo($process)
{
    $filetimes = GetFileTimestamps $process
    $TaskResults = GetTasks $process

    $ServiceResults = GetService $process
    
    $registryResults = SearchRegistry $process

    $AutostartFolderResults = AutostartFolders $process
    
    if ($search)
    {
        $FilesystemSearchResults = SearchFilesystem $process
    }

    #If above functions didn't return results, force variable to have something to maintain result array order
    if(!$taskresults){$TaskResults = ""}
    if(!$ServiceResults){$ServiceResults = ""}
    if(!$registryResults){$registryResults = ""}
    if(!$autostartFolderResults){$autostartFolderResults = ""}
    if(!$FilesystemSearchResults){$FilesystemSearchResults = ""}
    if(!$filetimes){$filetimes = ""}

    $results = $taskresults,$ServiceResults,$registryResults,$AutostartFolderResults,$filetimes,$FilesystemSearchResults

    return $results

}

Function GetSpecificProcessInfo($p)
{

    $gp_process = get-process -id $p

    $process = Get-WmiObject win32_process -filter "processid=$p"

    $LoadedDLLs = GetDLLs $gp_process

    $NetworkResults = GetNetworkActivity $p

    GetProcessLineage $process #the results of this are added to $global:process_table
    
    if(!$NetworkResults){$NetworkResults = ""}

    $ResultArray = $global:Process_table,$LoadedDLLs,$NetworkResults

    if(!$filepath)
    {
        $persistenceResults = GetPersistenceInfo($process) 
        $resultArray += $persistenceResults
    }

    

    return $ResultArray
}


#####################START OF ACTUAL SCRIPT PROCESSING#####################################


#If the user passes the -tree option, list all processes in tree format, otherwise write a simple list of all processes sorted by PPID
    if (!$p -and $tree -and !$filepath)
    {
        Show-ProcessTree
    } 
    elseif (!$p -and !$filepath) 
    {
        MyProcessList
    }


#if given a PID, and it exists, get info about it. otherwise return an error message stating PID doesn't exist
    if($p -and (get-process -id $p -ErrorAction SilentlyContinue) -and !$filename)
    {


       return GetSpecificProcessInfo $p
    
    }
    elseif ($p -and !$filename)
    {
    write-host "Process ID doesn't exist"
    return $false
    }

    if ($filepath)
    {


        #creating a new object with a property named ExecutablePath so we can use all the same functions
        $filenameContainer = New-Object -TypeName psobject
        $filenameContainer | Add-Member NoteProperty Executablepath  $filepath

        $persistenceResults = GetPersistenceInfo $filenameContainer

        $AllProcessResultsArray = @()

        $RunningProcesses = Get-WmiObject win32_process | where {$_.executablepath -like $filepath}

        if ($RunningProcesses)
        {
            foreach ($process in $RunningProcesses)
            {
                $AllProcessResultsArray += GetSpecificProcessInfo $process.processid
            }   
        }
        

        $fileresults = $persistenceResults
        $fileresults += $AllProcessResultsArray

        return $fileresults

    }




} ###This is the ending bracket for "FullScript" Function


Function VirusTotal($LoadedDLLs)
{
    #This is the master variable that will hold the data for all dll lookups
    $VTLookupResults = @()

    foreach($dll in $LoadedDLLs)
    {
        #Don't Look up DLLs created by Microsoft. This was done to reduce the number of lookups
        if ($dll.Company -ne "Microsoft Corporation")
        {
            $hash = $dll.hash

            #Try to check Virus Total for hash results. if no results found, return that information instead
            try
            {
            
                $test = Invoke-restmethod https://www.virustotal.com/api/v3/files/$hash -Headers @{"x-apikey"=$vtAPIKey} -ErrorAction SilentlyContinue
            
                #Convert Last Analysis Date from Epoch time to human readable time
                [datetime]$origin = '1970-01-01 00:00:00'
                $LastAnalysisDate = $origin.AddSeconds($test.data.attributes.last_analysis_date)

                #Create a temporary variable to store just the VirusTotal results we want, to be added to master variable
                $results = $test.data.attributes.last_analysis_stats
                $results | Add-Member NoteProperty Filename $dll.filename
                $results | Add-Member NoteProperty Hash $hash
                $results | Add-Member NoteProperty LastAnalysisDate $LastAnalysisDate
            }
            catch [System.Net.WebException] #Do this if Virus Total gives back a 404 error meaning no data found
            {
                
                $results = New-Object -TypeName psobject
                $results | Add-Member NoteProperty Filename $dll.filename
                $results | Add-Member NoteProperty Hash $hash
                $results | Add-Member NoteProperty LastAnalysisDate "Results not found"

            }
            catch
            {
                Write-host "Invoke-restmethod cmdlet not found"
            }
            #Add results to master variable
            $VTLookupResults += $results

            #VirusTotal API is rate limited (4 per minute with Free API). This Call to sleep ensures we don't break that limit
            sleep($vtsleep)
        }
    }

    return $VTLookupResults
}

Function FormatOutput($results, $vtresults)
{
    <#
        When processing the $Results variable, the array will contain data in different elements depending on if this script was
        executing searching for a PID or file path. Below details what information is stored in which element of the array.

        by PID
        (result data by index)

        0 = ProcessLineage
        1 = LoadedDLLs
        2 = Network Results
        3 = Scheduled Task Results
        4 = Service Results
        5 = Registry Results
        6 = Autostart Folder Results
        7 = File Timestamps
        8 = Filesystem Search Results

        By Filepath
        (Result data by index)

        0 = Scheduled Task Results
        1 = Service Results
        2 = Registry Results
        3 = Autostart Folder Results
        4 = File Timestamps
        5 = Filesystem Search Results
        6 = Process Lineage
        7 = LoadedDLLs
        8 = Network Results

        NOTE:: when searching by filepath, it also checks for running processes executing from that path, which is where 6-8 come in.
		it's possible for multiple processes to be running from that path, so there might be multiple sets of data related to 6-8. This
        is why these elements were moved to the end of the array, so we can iterate through these three elements as many times as there 
        where processes running.

    #>

    #Process and output all process information
    if (!$p -and $tree -and !$filepath)
    {

        if ($list)
        {
            $global:process_table | select name, pid, ppid, processuser, executablepath, commandline | fl
        }
        else
        {
            $global:process_table | select name, pid, ppid, processuser, executablepath, commandline | ft -AutoSize -wrap
        }
        if ($outpath)
        {
            $global:process_table | select name, pid, ppid, processuser, executablepath, commandline | export-Csv -NoTypeInformation ($outpath + "ProcessList.csv")
        }

    } 
    elseif (!$p -and !$filepath) 
    {

        if ($table)
        {
            $global:process_table | sort ppid | select name, pid, ppid, processuser, executablepath, commandline | ft -AutoSize -wrap
        }
        else
        {
            $global:process_table | sort ppid | select name, pid, ppid, processuser, executablepath, commandline 
        }
        if ($outpath)
        {
            $global:process_table | sort ppid | select name, pid, ppid, processuser, executablepath, commandline | export-Csv -NoTypeInformation ($outpath + "ProcessList.csv")
        }
    }
    
    if($p)
    {
        if($table)
        {
            Write-Host "Process Lineage in Reverse Order"
            $results[0] | Format-Table -auto -wrap
            
            Write-Host "Process Loaded DLLs"
            $results[1] | select modulename, filename, hash, company, fileversion | Format-Table -auto -Wrap

            if($results[2])
            {
                Write-Host "Network Information"
                $results[2] | Format-Table -auto -wrap
            }
            else
            {
                Write-Host "No Network Activity Associated with PID`r`n"
            }

            if($results[3])
            {
                Write-Host "Scheduled Task Information"
                $results[3] | select Hostname, Taskname, "Next Run Time", Status, "Last Run Time", Author, "Task to Run", "Run As User", "Schedule Type" | Format-Table -AutoSize -wrap
            }
            else
            {
                Write-Host "No Scheduled Tasks`r`n"
            }
            
            if($results[4])
            {
                Write-Host "Service Information"
                $results[4] | select SystemName, name, DisplayName, StartMode, Pathname, StartName, State | format-table -auto -Wrap
            }
            else
            {
                write-host "No Matching Services`r`n"
            }
            if($results[5])
            {
                Write-Host "Autostart Registry Keys Found"
                $results[5] | select key, value | format-table -auto -wrap
            }
            else
            {
                Write-Host "No Autostart Registry Keys Found"
            }
            if($results[6])
            {
                Write-Host "Autostart Folder Results`r`n"
                $results[6]
                Write-Host "`r`n"
            }
            else
            {
                Write-Host "No Matching Autostart Folder Entries`r`n"
            }
            if($results[7])
            {
                Write-Host "Executable Timestamps"
                $results[7] | select name, creationtime, creationtimeutc, lastwritetime, lastwritetimeutc, lastaccesstime, lastaccesstimeutc | format-table -auto -wrap
            }
            else
            {
                Write-host "Couldn't get executable timestamp information. File doesn't exist.`r`n"
            }
            if($results[8])
            {
                Write-Host "Files created within $search minutes of the executable in question"
                $results[8] | select creationtime, Fullname | format-table -AutoSize -wrap
            }
            else
            {
                Write-Host "Search not requested or no files crearted within search timeframe of executable in question`r`n"
            }

        }
        elseif($list -or !$outpath)
        {
            Write-Host "Process Lineage in Reverse Order"
            $results[0] | format-list
            
            Write-Host "Process Loaded DLLs"
            $results[1] | select modulename, filename, hash, company, fileversion | Format-List

            if($results[2])
            {
                Write-Host "Network Information"
                $results[2] | Format-List
            }
            else
            {
                Write-Host "No Network Activity Associated with PID`r`n"
            }

            if($results[3])
            {
                Write-Host "Scheduled Task Information"
                $results[3] | select Hostname, Taskname, "Next Run Time", Status, "Last Run Time", Author, "Task to Run", "Run As User", "Schedule Type" | Format-list
            }
            else
            {
                Write-Host "No Scheduled Tasks`r`n"
            }
            
            if($results[4])
            {
                Write-Host "Service Information"
                $results[4] | select SystemName, name, DisplayName, StartMode, Pathname, StartName, State | format-list
            }
            else
            {
                write-host "No Matching Services`r`n"
            }
            if($results[5])
            {
                Write-Host "Autostart Registry Keys Found"
                $results[5] | select key, value | format-list
            }
            else
            {
                Write-Host "No Autostart Registry Keys Found"
            }
            if($results[6])
            {
                Write-Host "Autostart Folder Results`r`n"
                $results[6] | format-list
                Write-Host "`r`n"
            }
            else
            {
                Write-Host "No Matching Autostart Folder Entries`r`n"
            }
            if($results[7])
            {
                Write-Host "Executable Timestamps"
                $results[7] | select name, creationtime, creationtimeutc, lastwritetime, lastwritetimeutc, lastaccesstime, lastaccesstimeutc | format-list
            }
            else
            {
                Write-host "Couldn't get executable timestamp information. File doesn't exist.`r`n"
            }
            if($results[8])
            {
                Write-Host "Files created within $search minutes of the executable in question"
                $results[8] | select creationtime, Fullname | format-list
            }
            else
            {
                Write-Host "Search not requested or no files crearted within search timeframe of executable in question`r`n"
            }
        }
        if($outpath)
        {
            $results[0] | export-csv -NoTypeInformation "$outpath$p-ProcessLineage.csv"
            
            $results[1] | select modulename, filename, hash, company, fileversion | export-csv -NoTypeInformation "$outpath$p-LoadedDLLs.csv"

            if($results[2])
            {
                $results[2] | export-csv -NoTypeInformation "$outpath$p-NetworkInformation.csv"
            }
            else
            {
                Write-Host "No Network Activity Associated with PID`r`n"
            }

            if($results[3])
            {
                $results[3] | select Hostname, Taskname, "Next Run Time", Status, "Last Run Time", Author, "Task to Run", "Run As User", "Schedule Type" | export-csv -NoTypeInformation "$outpath$p-ScheduledTasks.csv"
            }
            else
            {
                Write-Host "No Scheduled Tasks`r`n"
            }
            
            if($results[4])
            {
                $results[4] | select SystemName, name, DisplayName, StartMode, Pathname, StartName, State | export-csv -NoTypeInformation "$outpath$p-ServiceInformation.csv"
            }
            else
            {
                write-host "No Matching Services`r`n"
            }
            if($results[5])
            {
                $results[5] | select key, value | export-csv -NoTypeInformation "$outpath$p-AutostartRegistryKeys.csv"
            }
            else
            {
                Write-Host "No Autostart Registry Keys Found"
            }
            if($results[6])
            {
                $results[6] | export-csv -NoTypeInformation "$outpath$p-AutostartFolderResults.csv"
            }
            else
            {
                Write-Host "No Matching Autostart Folder Entries`r`n"
            }
            if($results[7])
            {
                $results[7] | select name, creationtime, creationtimeutc, lastwritetime, lastwritetimeutc, lastaccesstime, lastaccesstimeutc | export-csv -NoTypeInformation "$outpath$p-ExecutableTimestamps.csv"
            }
            else
            {
                Write-host "Couldn't get executable timestamp information. File doesn't exist.`r`n"
            }
            if($results[8])
            {
                $results[8] | select creationtime, Fullname | export-csv -NoTypeInformation "$outpathPID-$p-FilesystemSearchResults.csv"
            }
            else
            {
                Write-Host "Search not requested or no files crearted within search timeframe of executable in question`r`n"
            }
        }
    }

    #The elements in the array were re-ordered when given the filepath option. This was because multiple processes could be running from the same file
    # Which makes the length of the array variable while the rest is static. By putting it at the end, we can work through the dynamic length with a loop.
    elseif($filepath)
    {
        if($table)
        {
            if($results[0])
            {
                Write-Host "Scheduled Task Information"
                $results[0] | select Hostname, Taskname, "Next Run Time", Status, "Last Run Time", Author, "Task to Run", "Run As User", "Schedule Type" | Format-Table -AutoSize -wrap
            }
            else
            {
                Write-Host "No Scheduled Tasks`r`n"
            }
            
            if($results[1])
            {
                Write-Host "Service Information"
                $results[1] | select SystemName, name, DisplayName, StartMode, Pathname, StartName, State | format-table -auto -Wrap
            }
            else
            {
                write-host "No Matching Services`r`n"
            }
            if($results[2])
            {
                Write-Host "Autostart Registry Keys Found"
                $results[2] | select key, value | format-table -auto -wrap
            }
            else
            {
                Write-Host "No Autostart Registry Keys Found"
            }
            if($results[3])
            {
                Write-Host "Autostart Folder Results`r`n"
                $results[3]
                Write-Host "`r`n"
            }
            else
            {
                Write-Host "No Matching Autostart Folder Entries`r`n"
            }
            if($results[4])
            {
                Write-Host "Executable Timestamps"
                $results[4] | select name, creationtime, creationtimeutc, lastwritetime, lastwritetimeutc, lastaccesstime, lastaccesstimeutc | format-table -auto -wrap
            }
            else
            {
                Write-host "Couldn't get executable timestamp information. File doesn't exist.`r`n"
            }
            if($results[5])
            {
                Write-Host "Files created within $search minutes of the executable in question"
                $results[5] | select creationtime, Fullname | format-table -AutoSize -wrap
            }
            else
            {
                Write-Host "Search not requested or no files crearted within search timeframe of executable in question`r`n"
            }

            #Check if any results from the file running as a process. if so, process the data, otherwise skip it and move on.
            if($results[6])
            {
                ###start running process processing
                $i = 6 #starting at 6 to match the index position of results array
                do
                {
                    Write-Host "Process Lineage in Reverse Order"
                    $results[$i] | Format-Table -auto -wrap

                    Write-Host "Process Loaded DLLs"
                    $results[$i+1] | select modulename, filename, hash, company, fileversion | Format-Table -auto -Wrap

                    if($results[$i+2])
                    {
                        Write-Host "Network Information"
                        $results[$i+2] | Format-Table -auto -wrap
                    }
                    else
                    {
                        Write-Host "No Network Activity Associated with PID`r`n"
                    }

                    $i += 3

                }while($i -lt $results.count)
            }
            else
            {
                Write-Host "File not running as process"
            }

        }
        elseif($list -or !$outpath)
        {
            
            if($results[0])
            {
                Write-Host "Scheduled Task Information"
                $results[0] | select Hostname, Taskname, "Next Run Time", Status, "Last Run Time", Author, "Task to Run", "Run As User", "Schedule Type" | Format-list
            }
            else
            {
                Write-Host "No Scheduled Tasks`r`n"
            }
            
            if($results[1])
            {
                Write-Host "Service Information"
                $results[1] | select SystemName, name, DisplayName, StartMode, Pathname, StartName, State | format-list
            }
            else
            {
                write-host "No Matching Services`r`n"
            }
            if($results[2])
            {
                Write-Host "Autostart Registry Keys Found"
                $results[2] | select key, value | format-list
            }
            else
            {
                Write-Host "No Autostart Registry Keys Found"
            }
            if($results[3])
            {
                Write-Host "Autostart Folder Results`r`n"
                $results[3] | format-list
                Write-Host "`r`n"
            }
            else
            {
                Write-Host "No Matching Autostart Folder Entries`r`n"
            }
            if($results[4])
            {
                Write-Host "Executable Timestamps"
                $results[4] | select name, creationtime, creationtimeutc, lastwritetime, lastwritetimeutc, lastaccesstime, lastaccesstimeutc | format-list
            }
            else
            {
                Write-host "Couldn't get executable timestamp information. File doesn't exist.`r`n"
            }
            if($results[5])
            {
                Write-Host "Files created within $search minutes of the executable in question"
                $results[5] | select creationtime, Fullname | format-list
            }
            else
            {
                Write-Host "Search not requested or no files crearted within search timeframe of executable in question`r`n"
            }

            #Check if any results from the file running as a process. if so, process the data, otherwise skip it and move on.
            if($results[6])
            {
                ###start running process processing
                $i = 6 #starting at 6 to match the index position of results array
                do
                {
                    Write-Host "Process Lineage in Reverse Order"
                    $results[$i] | format-list
            
                    Write-Host "Process Loaded DLLs"
                    $results[$i+1] | select modulename, filename, hash, company, fileversion | Format-List

                    if($results[$i+2])
                    {
                        Write-Host "Network Information"
                        $results[$i+2] | Format-List
                    }
                    else
                    {
                        Write-Host "No Network Activity Associated with PID`r`n"
                    }
                    $i += 3
                }while($i -lt $results.count)
            }
            else
            {
                Write-Host "File not running as process"
            }

        }
        if($outpath)
        {
            $justFilename = ($filepath.split('\')[-1]).split('.')[0]

            if($results[0])
            {
                $results[0] | select Hostname, Taskname, "Next Run Time", Status, "Last Run Time", Author, "Task to Run", "Run As User", "Schedule Type" | export-csv -NoTypeInformation "$outpath$justFilename-ScheduledTasks.csv"
            }
            else
            {
                Write-Host "No Scheduled Tasks`r`n"
            }
            
            if($results[1])
            {
                $results[1] | select SystemName, name, DisplayName, StartMode, Pathname, StartName, State | export-csv -NoTypeInformation "$outpath$justFilename-ServiceInformation.csv"
            }
            else
            {
                write-host "No Matching Services`r`n"
            }
            if($results[2])
            {
                $results[2] | select key, value | export-csv -NoTypeInformation "$outpath$justFilename-AutostartRegistryKeys.csv"
            }
            else
            {
                Write-Host "No Autostart Registry Keys Found"
            }
            if($results[3])
            {
                $results[3] | export-csv -NoTypeInformation "$outpath$justFilename-AutostartFolderResults.csv"
            }
            else
            {
                Write-Host "No Matching Autostart Folder Entries`r`n"
            }
            if($results[4])
            {
                $results[4] | select name, creationtime, creationtimeutc, lastwritetime, lastwritetimeutc, lastaccesstime, lastaccesstimeutc | export-csv -NoTypeInformation "$outpath$justFilename-ExecutableTimestamps.csv"
            }
            else
            {
                Write-host "Couldn't get executable timestamp information. File doesn't exist.`r`n"
            }
            if($results[5])
            {
                $results[5] | select creationtime, Fullname | export-csv -NoTypeInformation "$outpath$justFilename-FilesystemSearchResults.csv"
            }
            else
            {
                Write-Host "Search not requested or no files crearted within search timeframe of executable in question`r`n"
            }

            #Check if any results from the file running as a process. if so, process the data, otherwise skip it and move on.
            if($results[6])
            {
                ###start running process processing
                $i = 6 #starting at 6 to match the index position of results array
                do
                {
                    #Get the PID of the first process found. Just trying to get the PID field from results gives an array of all PIDs within the process
                    # lineage, so we have t specify just the first PID in the array, which is the pid of the exectuable in quetsion
                    $currentPID = ($results[$i][0].pid)[0]

                    $results[$i] | export-csv -NoTypeInformation "$outpath$justFilename-$currentPID-ProcessLineage.csv"

                    $results[$i+1] | select modulename, filename, hash, company, fileversion | export-csv -NoTypeInformation "$outpath$justFilename-$currentPID-LoadedDLLs.csv"

                    if($results[$i+2])
                    {
                        $results[$i+2] | export-csv -NoTypeInformation "$outpath$justFilename-$currentPID-NetworkInformation.csv"
                    }
                    else
                    {
                        Write-Host "No Network Activity Associated with PID $currentPID`r`n"
                    }
                    
                    $i += 3

                }while($i -lt $results.count)
            }
            else
            {
                Write-Host "File not running as process"
            }

        }
    }
    
    if($vt -and $vtresults)
    {
        if($table)
        {
            $vtresults | select Filename, LastAnalysisDate, Undetected, type-unsupported, malicious, suspicious, failure, timeout, harmless, hash | Format-Table -AutoSize -wrap 
        }
        elseif($list -or !$outpath)
        {
            $vtresults | select Filename, LastAnalysisDate, Undetected, type-unsupported, malicious, suspicious, failure, timeout, harmless, hash | Format-list
        }
        if($outpath)
        {
            if($p)
            {
                $vtresults | select Filename, LastAnalysisDate, Undetected, type-unsupported, malicious, suspicious, failure, timeout, harmless, hash | Export-Csv -NoTypeInformation "$outpath$p-VirusTotal.csv"
            }
            elseif($filepath)
            {
                $vtresults | select Filename, LastAnalysisDate, Undetected, type-unsupported, malicious, suspicious, failure, timeout, harmless, hash | Export-Csv -NoTypeInformation "$outpath$justFilename-VirusTotal.csv"
            }
        }
    }
    elseif($vt -and !$vtresults)
    {
        Write-host "No Results from Virus Total. This likely means all DLLs loaded are from Microsoft or the file is not a running process."
    }





}



if ($computer)
{
    if(!$cred)
    {
        $cred = Get-Credential
    }

    $temp = Invoke-Command -ComputerName $computer -cred $cred -ScriptBlock ${function:FullScript} -ArgumentList $p,$tree,$search,$filepath
    
    if($vt -and $p)
    {
       $vtresults = VirusTotal $temp[1]
    }
    elseif($vt -and $filepath)
    {
        if($temp[7])
        {
            $vtresults = VirusTotal $temp[7]
        }
    }

    if($temp -ne $false)
    {
        FormatOutput $temp $vtresults
    }
}
else
{
    
    $temp = FullScript $p $tree $search $filepath

    if($vt -and $p)
    {
        $vtresults = VirusTotal $temp[1]
    }
    elseif($vt -and $filepath)
    {
        if($temp[7])
        {
            $vtresults = VirusTotal $temp[7]
        }
    }

    if($raw)
    {
        $temp
    }
    if(($temp -ne $false) -and !$raw)
    {
        FormatOutput $temp $vtresults
    }
}



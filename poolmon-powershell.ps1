# Adapted from https://github.com/stevea78/poolmon-powershell


<#

.SYNOPSIS
	.

.DESCRIPTION
	View kernel memory pool tag information

.PARAMETER tags
	comma separated list of tags to display

.PARAMETER values
	comma separated list of values to display

.PARAMETER sortvalue
	value to sort by

.PARAMETER sortdir
	direction to sort (ascending|descending)

.PARAMETER top
	top X records to display

.PARAMETER view
	output view (table|csv|grid)

.PARAMETER tagfile
	file containing tag information

.PARAMETER loop
	loop interval in seconds

.EXAMPLE
	.\poolmon-powershell.ps1 -tags FMfn -values DateTime,Tag,PagedUsedBytes,Binary,Description -tagfile pooltag.txt -loop 5 -view csv
	"DateTime","Tag","PagedUsedBytes","Binary","Description"
	"2019-07-24T12:21:57","FMfn","199922400","fltmgr.sys","NAME_CACHE_NODE structure"
	"2019-07-24T12:22:02","FMfn","199941136","fltmgr.sys","NAME_CACHE_NODE structure"
	"2019-07-24T12:22:07","FMfn","199878016","fltmgr.sys","NAME_CACHE_NODE structure"

#>

param (
	[string]$tags,
	[string]$tagsExp,
	[string]$driverPath,
	[string]$values,
	[string]$sortvalue = 'TotalUsed',
	[string]$sortdir = 'Descending',
	[int]$top = 0,
	[string]$view = 'table',
	[string]$tagfile = 'pooltag.txt',
	[int]$loop = 0
)


function Get-Date-SplunkFormat {
    param (
        [parameter(Mandatory=$false)][datetime]$inputDate=(Get-Date)
    )

    $inputDateString = $inputDate.ToString('MM-dd-yyyy HH:mm:ss.fff zzzz')
    $inputDateParts = $inputDateString -split " "
    $inputDateZone = $inputDateParts[2] -replace ":",""
    $outputDateString  = "$($inputDateParts[0]) $($inputDateParts[1]) $($inputDateZone)"
    return $outputDateString
}

function format-splunkLogFromObject {
    param (
        [parameter(Mandatory=$true)]$object
    )
    $Properties = ($object | get-member -MemberType NoteProperty).Name
    $Records = @()
    foreach ($item in $object) {
        $Record = "$(Get-Date-SplunkFormat) -"

        foreach ($Property in $Properties) {
            $Record += " $($Property)=`"$($item.$($property))`""
        }
        $Records += $Record
    }
    return $Records
}


Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Win32 {
	public enum NT_STATUS
	{
		STATUS_SUCCESS = 0x00000000,
		STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005),
		STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004)
	}
	public enum SYSTEM_INFORMATION_CLASS
	{
		SystemPoolTagInformation = 22,
	}
	[StructLayout(LayoutKind.Sequential)]
	public struct SYSTEM_POOLTAG
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] Tag;
		public uint PagedAllocs;
		public uint PagedFrees;
		public System.IntPtr PagedUsed;
		public uint NonPagedAllocs;
		public uint NonPagedFrees;
		public System.IntPtr NonPagedUsed;
	}
	public class PInvoke {
		[DllImport("ntdll.dll")]
		public static extern NT_STATUS NtQuerySystemInformation(
		[In] SYSTEM_INFORMATION_CLASS SystemInformationClass,
		[In] System.IntPtr SystemInformation,
		[In] int SystemInformationLength,
		[Out] out int ReturnLength);
	}
}
'@

Function Get-Pool() {
	if ($tagfile) {
		if (Test-Path $tagfile) {
			$tagFileHash = $null
			$tagFileHash = new-object System.Collections.Hashtable
			foreach($line in Get-Content $tagfile) {
				if(($line.trim() -ne '') -and ($line.trim() -like '*-*-*') -and ($line.trim().SubString(0,2) -ne '//') -and ($line.trim().SubString(0,3) -ne 'rem')){
					$t,$b,$d = $line.split('-')
					$t = $t.trim()
					$b = $b.trim()
					$d = $d.trim()
					if (!($tagFileHash.containsKey($t))) {
						$tagFileHash.Add($t,"$b|$d")
					}
				}
			}
		}
	}
	$ptrSize = 0
	while ($true) {
		[IntPtr]$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ptrSize)
		$ptrLength = New-Object Int
		$tagInfo = [Win32.PInvoke]::NtQuerySystemInformation([Win32.SYSTEM_INFORMATION_CLASS]::SystemPoolTagInformation, $ptr, $ptrSize, [ref]$ptrLength)
		if ($tagInfo -eq [Win32.NT_STATUS]::STATUS_INFO_LENGTH_MISMATCH) {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
			$ptrSize = [System.Math]::Max($ptrSize,$ptrLength)
		}
		elseif ($tagInfo -eq [Win32.NT_STATUS]::STATUS_SUCCESS) {
			break
		}
		else {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
			"An error occurred getting SystemPoolTagInformation"
			return
		}
	}
	$tags = $tags -Split ','
	$datetime = Get-Date-SplunkFormat
	$systemPoolTag = New-Object Win32.SYSTEM_POOLTAG
	$systemPoolTag = $systemPoolTag.GetType()
	$size = [System.Runtime.InteropServices.Marshal]::SizeOf([type]([Win32.SYSTEM_POOLTAG]))
	$offset = $ptr.ToInt64()
	$count = [System.Runtime.InteropServices.Marshal]::ReadInt32($offset)
	$offset = $offset + [System.IntPtr]::Size
	for ($i=0; $i -lt $count; $i++){
		$entryPtr = New-Object System.Intptr -ArgumentList $offset
		$entry = [system.runtime.interopservices.marshal]::PtrToStructure($entryPtr,[type]$systemPoolTag)
		$tag = [System.Text.Encoding]::Default.GetString($entry.Tag)
		if (!$tags -or ($tags -and $tags -contains $tag)) {
			$tagResult = $null
			$tagResult = [PSCustomObject]@{
				Tag = $tag.trim()
				PagedAllocs = [int64]$entry.PagedAllocs
				PagedFrees = [int64]$entry.PagedFrees
				PagedDiff = [int64]$entry.PagedAllocs - [int64]$entry.PagedFrees
				PagedUsedBytes = [int64]$entry.PagedUsed
				NonPagedAllocs = [int64]$entry.NonPagedAllocs
				NonPagedFrees = [int64]$entry.NonPagedFrees
				NonPagedDiff = [int64]$entry.NonPagedAllocs - [int64]$entry.NonPagedFrees
				NonPagedUsedBytes = [int64]$entry.NonPagedUsed
				TotalUsedBytes = [int64]$entry.PagedUsed + [int64]$entry.NonPagedUsed
			}
			if ($tagFileHash) {
				if ($tagFileHash.containsKey($tag)) {
					$Bin,$BinDesc = $tagFileHash.$tag.split('|')
					$tagResult | Add-Member NoteProperty 'Binary' $Bin
					$tagResult | Add-Member NoteProperty 'Description' $BinDesc
				} else {
					$tagResult | Add-Member NoteProperty 'Binary' ''
					$tagResult | Add-Member NoteProperty 'Description' ''
				}
			}
            $tagResult
		}
		$offset = $offset + $size
	}
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
}
$expression = 'Get-Pool'
if ($sortvalue) {
	$expression += "|Sort-Object -Property $sortvalue"
	if ($sortdir -eq 'Descending') {
		$expression += ' -Descending'
	}
}
if ($top -gt 0 -and !$tagsExp) {
	$expression += "|Select-Object -First $top"
}
if ($values) {
	$expression += "|Select-Object $values"
}

$Results = Invoke-Expression $expression


# exclude results whose paged and nonpaged differences are 0
$Results = $Results | ?{$_.PagedDiff -ne 0 -or $_.NonPagedDiff -ne 0}


# exclude results whose tags match regular expression privded as command line argument
if ($tagsExp) {
    $Results = $Results | ?{$_.tag -match $tagsExp}
}

# exclude results whose tags are not included in strings of specified driver in command line argument
if ($driverpath) {
    if (Test-Path -Path $driverPath) {
        $PossibleFlags = & 'C:\Users\admin\Downloads\SysinternalsSuite\strings.exe' -accepteula $driverpath | Select-String -Pattern "^\w{3,4}$"
        $PossibleFlags = $PossibleFlags -join "|"
        $tagsExp = "`($($PossibleFlags)`)"
        $Results = $results | ?{$_.tag -match $tagsExp}
    }   
}

format-splunkLogFromObject -object $Results 


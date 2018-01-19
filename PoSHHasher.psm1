Function Get-Hash {
    
    <#
        .SYNOPSIS
            Hashes a given input

        .DESCRIPTION
            This cmdlet takes a given input(s) in the form of a string and allows you to hash it using a number of common algorithms. It also allows you to salt the hash.

        .PARAMETER String
            The string written in ASCII characters that you wish to hash.

        .PARAMETER Algorithm
            The Algorithm you wish to hash your string with.

            Available algorithms are SHA1 , SHA256, SHA512, MD5

        .PARAMETER Salt
            Allows you to specify your own salt for hashing a string.

        .PARAMETER RandomSalt
            A switch that allows you to use a random salt. The script will ensure that if there are multiple input strings, that it will generate a new salt for each.

        .EXAMPLE
            PS C:\> Get-Hash -String "Hello" -Algorithm MD5
            8B1A9953C4611296A827ABF8C47804D7
        
        .EXAMPLE
            PS C:\> Get-Hash -String "Hello","World" -Algorithm MD5
            8B1A9953C4611296A827ABF8C47804D7
            F5A7924E621E84C9280A9A27E1BCB7F6

        .EXAMPLE
            PS C:\> Get-Hash -String "Hello","World" -Algorithm MD5 -Salt "asdfjkl;"
            HashID Hash                             Salt     Algorithm
            ------ ----                             ----     ---------
                1 80E88991D81EF63E36F87F564620F2AC asdfjkl; MD5
                2 A8E479B56911616464219ED54F27939D asdfjkl; MD5

        .EXAMPLE
            PS C:\> Get-Hash -String "Hello","World" -Algorithm MD5 -RandomSalt
            HashID Hash                             Salt           Algorithm
            ------ ----                             ----           ---------
                1 5678994712FF69DF4AE702D1DBF542D7 $po^&0FJf3V#Xe MD5
                2 D02AF30A555598FC0F49959D2A83E47B aST3lzeiq&g^u( MD5

        .EXAMPLE
            PS C:\> Get-Hash -String "Hello","World" -Algorithm SHA1
            F7FF9E8B7BB2E09B70935A5D785E0CC5D9D0ABF0
            70C07EC18EF89C5309BBB0937F3A6342411E1FDD

        .EXAMPLE
            PS C:\> Get-Hash -String "Hello","World" -Algorithm SHA256
            185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969
            8AE647DC5544D227130A0682A51E30BC7777FBB6D8A8F17007463A3ECD1D524

        .EXAMPLE
            PS C:\> Get-Hash -String "Hello","World" -Algorithm SHA512
            3615F80C9D293ED7402687F94B22D58E529B8CC7916F8FAC7FDDF7FBD5AF4CF777D3D795A7A00A16BF7E7F3FB9561EE9BAAE480DA9FE7A18769E71886B03F315
            8EA77393A42AB8FA92500FB077A9509CC32BC95E72712EFA116EDAF2EDFAE34FBB682EFDD6C5DD13C117E08BD4AAEF71291D8AACE2F890273081D0677C16DF0F
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ParameterSetName='NoSalt',Mandatory=$True,Position=0)]
        [Parameter(ParameterSetName='SpecifySalt',Mandatory=$True,Position=0)]
        [Parameter(ParameterSetName='RandomSalt',Mandatory=$True,Position=0)]
        [String[]]$String,

        [Parameter(ParameterSetName='NoSalt',Mandatory=$True,Position=1)]
        [Parameter(ParameterSetName='SpecifySalt',Mandatory=$True,Position=1)]
        [Parameter(ParameterSetName='RandomSalt',Mandatory=$True,Position=1)]
        [ValidateSet("SHA1","SHA256","SHA512","MD5")]
        [String]$Algorithm,

        [Parameter(ParameterSetName='SpecifySalt',Mandatory=$True,Position=2)]
        [String]$Salt,

        [Parameter(ParameterSetName='RandomSalt',Mandatory=$True,Position=2)]
        [Switch]$RandomSalt
    )

    Begin {
        
        #Initiates a new instance of the .Net Hash Algorithm class with the inputted hash algorithm of choice
        $HashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

    }
    
    Process {

        #Create an Empty array
        [Array]$Output_Array = @()
        
        #Change the name of the string variable for ease of use in the foreach loop below
        $InputStrings = $String

        #Create a HashID variable with a value of 0
        $HashID = 0
        
        #Loop through each input string
        ForEach ($InputString in $InputStrings) {

            #Add one to the HashID
            $HashID++

            
            #If the Random salt parameter is specified, use the Get-RandomSalt Cmdlet and append the random salt to the end of the string
            If ($RandomSalt) {
                $Salt = Get-RandomSalt
            }
            
            #If the Salt parameter is not null, take the input string and append the salt to the end of it
            If ($Salt) {

                $SaltUsed = $True
                $InputString = $InputString + $Salt

            }

            #Initiates a new instance of the .Net String Builder class with a capacity of 50 characters
            $StringBuilder = [System.Text.StringBuilder]::new(50)
            
            #The input string is converted to a UTF8 Byte array, and then hashed with the compute hash method of the HashAlgorithm class. 
            $HashAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString)) | ForEach-Object {
                
                #Then each byte in the array is enumerated and converted to hexadecimal and appended to the string builder object
                [void] $StringBuilder.Append($_.ToString("x2"))

            }

            #Hash is placed in a variable as a string in all upper-case letters
            $Hash = $StringBuilder.ToString().ToUpper()

            #If a salt was used in the hash
            If ($SaltUsed -eq $True) {

                #Make a PS custom object so that you can associate the hash to the salt
                $Obj = [PSCustomObject]@{

                    HashID = $HashID
                    Hash = $Hash
                    Salt = $Salt
                    Algorithm = $Algorithm

                }

                #Add the object to the empty array
                $Output_Array += $Obj

            } Else {
                
                #Otherwise just output the hash string
                Write-Output $Hash

            }

        }
        
        # If the Output array isn't empty, output it
        If ($Output_Array -ne $Null) {

            Write-Output $Output_Array

        }

    }

    End {

    }

}

Function Get-RandomSalt {

    <#

        .SYNOPSIS
            Creates a random salt used for hashing

        .DESCRIPTION
            This function creates a 14 character alpha-numeric + symbols salt that can be used in addition to a string to "salt" a hash

        .EXAMPLE
            PS C:\> Get-RandomSalt
            blNKt@n3%eY^8P

    #>

    #List of possible characters the salt can use
    $SaltDictionary = "a","b","c","d","e","f","g","h","i","j","k","l","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D"`
    ,"E","F","G","H","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","0","1","2","3","4","5","6","7","8"`
    ,"9","!","@","#","$","%","^","&","*","(",")"

    #Pick 14 random characters from the list
    $Salt = $SaltDictionary | Get-Random -Count 14
    #Take the array of 14 caracters and concatinate them into a string
    $Salt = [String]::Concat($Salt)

    #Output the Salt
    Write-Output $Salt

}

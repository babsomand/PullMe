#Importerer
Import-Module ActiveDirectory

# Tager output fra csv filen.
$users = Import-Csv -Path "C:\Users\Sebastian\Desktop\users.csv"
$creds = Get-Credential
Invoke-Command -ComputerName 10.14.2.203 -Credential $creds -ScriptBlock {
#Tager hver bruger i csv filen og udskriver nedenstående informationer om dem.
foreach ($user in $users) {
    Write-Output "Creating user: $($user.Username)"
    Write-Output "First Name: $($user.FirstName)"
    Write-Output "Last Name $($user.LastName)"
    Write-Output "Password $($user.Password)"
    Write-Output "OU $($user.OU)"
    # Write-Output "DC $($user.DC)"

# Adder brugeren til Active Directory
try {
    #Opretter brugerens specifikationer
    New-ADUser  -Name $user.Username
                -GivenName $user.FirstName
                -Surname $user.LastName
                -UserPrincipalName "$($user.Username)@$($user.DC)"
                -SamAccountName $user.Username
                -PasswordNeverExpires $true
                -AccountPassword (ConvertTo-SecureString -AsPlainText $user.Password -Force)
                -Path "OU=$user.OU,DC=$($user.DC)"
                -Enabled $true

        Write-Output "User creation completed: $($user.Username)"
    }
    catch {
        Write-Output "User creation failed for $($user.Username). Error: $_"        
        }
}

}

#Adder Active Directory users
#New-ADUser -Name $user.Username -GivenName $User.FirstName -Surname $user.LastName -UserPrincipalName $User.Password
#Udskriver om brugeren blev oprettet korrekt eller om det fejlede.
#    if (New-ADUser == true) {
#        Write-Output "User creation completed"
#    }
#    if (New-ADUser == false) {
#        Write-Output "User creation failed"
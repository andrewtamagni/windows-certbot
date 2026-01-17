<#
This script works with the windows Certbot 1.24.0 install to create a .pfx certificate if a new certificate is detected in the Certbot live directory.  It relies on the current in use
.pfx certificate for a system to be located in the PfxShareDir directory.  The name must match the corresponding sub-directory for the certificate in the Certbot live directory. The
script will extract the thumbprint for all the .pfx certificates in the PfxShareDir directory and compare it with the thumbprint of the corresponding certificate in the CertbotLiveDir
directory.  If a new certificate is detected in the CertbotLiveDir directory, the .pfx file for the new certificate is created and placed in the PfxShareDir.  The expiring .pfx 
certificate is placed in the PfxArchiveDir directory and has the expiration date appended to the filename.  A google calendar event is also created and posted to the designated google
calendar for the expiration of the new certificate.  The CalendarNoticeDays variable is set to a negative number for the amount of days warning desired for the calendar event.

This script also relies on Powershell 7 and OpenSSL 1.1.1.  Powershell 7 is required for the necessary PFX modules.  OpenSSL 1.1.1 is required for interoperability of PFX certificates
between the Windows Server 2016 operating system and greater.  The secret.encrypted file used to set the PFX PW must be generated before running the script.  The Client Secret JSON file
for the Google Cloud Project associated with the app used to post to the calendar event must also be in the same directory as this script.

Run GetGoogleRefreshToken.ps1 first to add the refresh token to the Client Secret JSON file before running this script.
#>

# Save .pfx file PW as Secure String.  You must use Powershell ISE to get the secure string popup
# Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File -FilePath "C:\Certbot\secret.encrypted"

# Set Global Variables
$global:PfxShareDir = '<Directory containing PFX certificates>'
$global:CertbotLiveDir = '<Certbot Live Directory>'
$global:PfxArchiveDir = '<PFX Archive Directory>'
$global:LogFile = '<Log File Path>.log'
$global:calendarId = '<Google Calendar ID>'
$global:CalendarNoticeDays = '<A negative integer for the number of days before expiration to post the calendar event>'

# Other variables
$global:date = get-date -uformat '%Y%m%d'
$global:CertsToReplace = @()
$global:ErrorCount = 0
$global:emailBody = ''
$global:sub = ''
$global:Hostname = [System.Net.Dns]::GetHostName()

# Variables to un-encrypt PFX file from secure PW string file.
$global:EncryptedData = Get-Content 'C:\Certbot\secret.encrypted' # Location of encrytpted secret file
$global:EncryptedPW = ConvertTo-SecureString $EncryptedData # Get-PfxCertificate requires PW to be secure string
$global:ClearPW = ConvertFrom-SecureString -SecureString $EncryptedPW -AsPlainText #Convert PW to clear text for OpenSSL


# PublishGoogleCalendarEvent Variables
$clientSecretJsonFile = "$PSScriptRoot\client_secret.json"
$clientSecretJson = Get-Content -Raw -Path $clientSecretJsonFile | ConvertFrom-Json
$global:clientId = $clientSecretJson.installed.client_id
$global:clientSecret = $clientSecretJson.installed.client_secret
$global:refreshToken = $clientSecretJson.installed.refresh_token

# Define certificate class variables
class Certificate {
    [string]$Name
    [string]$CurrentIssuedDate
    [string]$CurrentExpireDate
    [string]$CurrentThumbprint
    [string]$CertbotIssuedDate
    [string]$CerbotExpireDate
    [string]$CertbotThumbprint
    [System.DateOnly]$CertbotExpireNoticeDate
}

# This function takes an argument for an event date (format: YYYY-MM-DD) and a for an event title
# string, then inserts the event into a Google Calendar.  The event is a simple all-day (single day)
# event without any guests. It requires the location for the client_secret JSON file from the GCP
# Project and calendarId to be set.  The GetGoogleRefreshToken.ps1 script needs to be executed first
# in order for refresh token to be added to the client_secret.json file.
function PublishGoogleCalendarEvent($EventDate, $EventSummary) {
    # Format the Refresh Token JSON payload for Access Token Request
    $refreshTokenParams = @{
        client_id       = $clientId
        client_secret   = $clientSecret
        refresh_token   = $refreshToken
        grant_type      = "refresh_token"
    }

    # Request Google API Access Token to use for Calendar API call
    $requestUri = "https://www.googleapis.com/oauth2/v4/token"
    $tokens = Invoke-RestMethod -Uri $requestUri -Method POST -Body $refreshTokenParams
    $accessToken = $tokens.access_token
    
    # Format JSON payload for Google Calendar API POST
    # https://developers.google.com/calendar/api/v3/reference/events/insert
    $PublishEventParams = @{
        summary = $EventSummary
        start   = @{date=$EventDate}
        end     = @{date=$EventDate}
    }

    # Call to Google Calendar API to insert calendar event
    $PostEventsParams = @{
        Uri         = "https://www.googleapis.com/calendar/v3/calendars/$calendarId/events"
        Headers     = @{ 'Authorization' = "Bearer $accessToken" }
        Method      = 'POST'
        Body        = ConvertTo-Json($PublishEventParams)
        ContentType = 'application/json'
    }
    Invoke-RestMethod @PostEventsParams
}

function GetPfxCertName($PfxPath) {
    $PfxName = $PfxPath.split('\')[-1].split('.')[0]
    $PfxName
}

# Format the date string to append to the archived cert file name and format the date the Google API Call.
function FormatDateString($ExpDate) {    
    $CreationDate = [System.DateOnly]::ParseExact($ExpDate, 'MM/dd/yyyy', $null)
    $CreationDate.ToString("yyyy-MM-dd")
}

# Archive the older .pfx certificate
function ArchiveCert($NewCertificate) {
    Move-Item -Path "$($PfxShareDir)$($NewCert.Name).pfx" -Destination "$($PfxArchiveDir)/$($NewCert.Name)_$(FormatDateString($NewCert.CurrentExpireDate)).pfx"
}

# Grab information on all PFX certs in the PfxShareDir directory (current certificates).  Also grab the information for the corresponding
# certificate in the CertbotLiveDir directory (new certificates).
function NewCertCheck($Certificate) {
    # Create the certificate class object
    $Cert = [Certificate]::new()
    $Cert.Name = GetPfxCertName($Certificate)
    
    # Get the thumbprint along with the issued and expiration dates of the .PFX cert and remove the time of day
    $Cert.CurrentIssuedDate = (Get-PfxCertificate -FilePath $Certificate -Password $EncryptedPW).NotBefore
    $Cert.CurrentExpireDate =  (Get-PfxCertificate -FilePath $Certificate -Password $EncryptedPW).NotAfter
    $Cert.CurrentIssuedDate = ($Cert.CurrentIssuedDate).split(' ')[0]
    $Cert.CurrentExpireDate = ($Cert.CurrentExpireDate).split(' ')[0]
    $Cert.CurrentThumbprint = (Get-PfxCertificate -FilePath $Certificate -Password $EncryptedPW).Thumbprint
    
    # Extract information from the corresponding .pem certifcate in the certbot live directory    
    $PemPath = Join-Path -Path "$($CertbotLiveDir)$($Cert.Name)" -ChildPath 'cert.pem'
    $PemCert = Get-Content $PemPath
    $PemCertData = [System.Text.Encoding]::UTF8.GetBytes($PemCert)
    $CertString = [System.Convert]::ToBase64String($PemCertData)
    $Cert.CertbotIssuedDate = ([System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($CertString))).NotBefore
    $Cert.CerbotExpireDate = ([System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($CertString))).NotAfter
    $Cert.CertbotIssuedDate = ($Cert.CertbotIssuedDate).split(' ')[0]
    $Cert.CerbotExpireDate = ($Cert.CerbotExpireDate).split(' ')[0]
    $Cert.CertbotThumbprint = ([System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($CertString))).Thumbprint
    [System.DateOnly]$NoticeDate = ($Cert.CerbotExpireDate).split(' ')[0]
    $NoticeDate = $NoticeDate.adddays($CalendarNoticeDays)
    $Cert.CertbotExpireNoticeDate = $NoticeDate
    $Certificates += $Cert

    # Compare thumbprints to see if new certificate is availible.  If so, add object to the $CertsToReplace array
    If ($Cert.CurrentThumbprint -ne $Cert.CertbotThumbprint) {
        $global:CertsToReplace += $Cert
    }
}

# Grab server name from .pfx file path string
function sendmail() {
    #SMTP server name
    $smtpServer = "smtp.org.edu"

    #Creating a Mail object
    $msg = new-object Net.Mail.MailMessage

    #Creating SMTP server object
    $smtp = new-object Net.Mail.SmtpClient($smtpServer)
    
    # Format email body     
    $emailBody = $emailBody | Format-Table | Out-String
    
    #Email structure
    $msg.From = "$($Hostname)@org.edu"
    $msg.ReplyTo = "$($Hostname)@org.edu"
    $msg.To.Add("user@org.edu")
    $msg.subject = $sub
    $msg.body = $emailBody
    
    #Sending email
    $smtp.Send($msg)
}

##### MAIN SCRIPT ####

# Check all current .pfx certs for new certs in the Certbot Live Directory.  Catch any errors
foreach ($PfxCert in ((Get-ChildItem -Path $PfxShareDir).FullName)) {
    Try{
        NewCertCheck($PfxCert)
    }
    Catch {
        Write-Output ("$($date) - There was an error checking for a new $(GetPfxCertName($PfxCert)) Certbot Cert") | Out-File -FilePath $LogFile -Append       
        $ErrorCount = $ErrorCount + 1
    }    
}
#For testing only
#$CertsToReplace

# If there are new certs available, archive the old cert and create the new one. Catch any errors and send notification email if there are any
# or if there is a new cert available.
If ($CertsToReplace.count -gt 0) {
    foreach ($NewCert in $CertsToReplace) {

        # Archive old .PFX certificate and generate new one.  Create Log entry and email notice
        Try {
            ArchiveCert($NewCert)
            openssl pkcs12 -export -in "$($CertbotLiveDir)$($NewCert.Name)\cert.pem" -inkey "$($CertbotLiveDir)$($NewCert.Name)\privkey.pem" `
            -out "$($PfxShareDir)$($NewCert.Name).pfx" -password pass:$ClearPW            
                    
            # Generate Log Entry
            Write-Output ("$($date) - The certificate for $($NewCert.Name) is expiring on $($NewCert.CurrentExpireDate)") | Out-File -FilePath $LogFile -Append
            Write-Output ("     The new certificate for $($NewCert.Name) has") | Out-File -FilePath $LogFile -Append
            Write-Output ("     been published and expires on $($NewCert.CerbotExpireDate)") | Out-File -FilePath $LogFile -Append

            # Generate Email, clear subject and emailBody variables
            $emailBody = @()
            $sub = ''
            $sub = Write-Output ("New $($NewCert.Name) Certifcate Published")
            $emailBody += Write-Output ("The certificate for $($NewCert.Name) is expiring on $($NewCert.CurrentExpireDate).")
            $emailBody += Write-Output ("The new certificate has been published on $($Hostname) and expires on $($NewCert.CerbotExpireDate)")
            sendmail
        }
        Catch {
            Write-Output ("$($date) - There was an error creating the new $($NewCert.name) Certbot Cert") | Out-File -FilePath $LogFile -Append
            $ErrorCount = $ErrorCount + 1
        }

        # Post Expiration Notice on Google Calendar, catch any errors.
        Try {
            
            $EventDate = "$(FormatDateString($NewCert.CertbotExpireNoticeDate))"
            $EventTitle = "$($NewCert.Name) - Cert Expiration $($NewCert.CerbotExpireDate)"
            PublishGoogleCalendarEvent $EventDate $EventTitle
        }
        Catch {
            Write-Output ("$($date) - There was an error creating the new $($NewCert.name) Google Calendar Event") | Out-File -FilePath $LogFile -Append
            $ErrorCount = $ErrorCount + 1
        }
    }
}

# Log a success, generate an email for any failures
if ($errorCount -eq 0) {
    Write-Output ("$($date) - The Acme Publish script ran successfully.") | Out-File -FilePath $LogFile -Append
    exit(0)    
}
else {
    $emailBody = @()
    $sub = Write-Output ("Acme Publishing Script Errors on $($Hostname)")
    $emailBody += Write-Output ("Please check the log entries in $($LogFile) on $($Hostname).  The Acme Publishing script is experiencing errors.")
    sendmail
    exit(1)
}
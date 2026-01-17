<#
This script  checks a directory for .pfx certificate files.  If there are any certificates expiring within the amount of days specified in the $expiryThreshold 
variable, an HTML email report is sent off to the recipients configured in $msgTo.

The script also relies on Powershell 7 and OpenSSL 1.1.1.  Powershell 7 is required for the necessary PFX modules.  OpenSSL 1.1.1 is required for interoperability 
of PFX certificates between the Windows Server 2016 operating system and greater.  The secret.encrypted file used to set the PFX PW must be generated before executing 
the script.  The Client Secret JSON file for the Google Cloud Project associated with the app used to post to the calendar event must also be in the same directory 
as this script.
#>

# Save .pfx file PW as Secure String.  You must use Powershell ISE to get the secure string popup
# Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File -FilePath "C:\Certbot\secret.encrypted"

# Variables
$date = get-date -uformat '%Y%m%d'
$pfxDir = "<Directory containing the PFX certificates>"
$expiryThreshold = '<integer for the number of days out to look for expiring certificates>'
$encryptedData = Get-Content 'C:\Certbot\secret.encrypted' # Location of encrytpted secret file
$logFile = '<Log File>.log'
$expiringCertificates = @() # array to store the expiring certificates
$errorCount = 0

# Email Variables
$msgSubject = "Upcoming Windows Certbot Automated Renewals - $($expiryThreshold) Days"
$msgTo = "<recipients of the email report>"
$msgSmtpServer = "<smtp email server>"

# Function to send email
Function sendEmailFromHost{
    param(
        [Array]$to,
        [Array]$body,
        [String]$subject,
        [String]$smtpServer,
        [switch]$bodyAsHtml  # New parameter to indicate if the body is HTML or plain text
    )    
    $msgFrom = (Get-WmiObject win32_computersystem).DNSHostName + "." + (Get-WmiObject win32_computersystem).Domain
    $msg = new-object Net.Mail.MailMessage
    $smtp = new-object Net.Mail.SmtpClient($smtpServer)
    #$emailBody = $msgBody | Format-List | Out-String
    $msg.From = "no-reply@" + $msgFrom
    foreach ($recipient in $msgTo){$msg.To.Add($recipient)}
    $msg.subject = $msgSubject
    
    # Set the email body format to HTML
    if ($bodyAsHtml) {
        $msg.IsBodyHtml = $true
    }
    $msg.body = $body
    $smtp.Send($msg)
}

# Extract encrypted PW from credentials file
$encryptedPW = ConvertTo-SecureString $encryptedData # Get-PfxCertificate requires PW to be secure string

# Check all certificates in the PFX directory, filter out any files without .pfx extension and check for errors
foreach ($pfxCert in (Get-ChildItem -Path $pfxDir -Filter "*.pfx").FullName) {
    Try{
        $certData = Get-PfxCertificate -FilePath $pfxCert -Password $encryptedPW
        
        # Check if the certificate is expiring within the threshold
        if ($certData.NotAfter -le (Get-Date).AddDays($expiryThreshold)) {
            # Add the expiring certificate to the array
            $expiringCertificates += $certData
        }        
    }
    Catch {
        Write-Output ("$($date) - ERROR - issues checking certificate at $($pfxCert)") | Out-File -FilePath $logFile -Append       
        $errorCount = $errorCount + 1
    }
}

# Generate email and kill script if there are issues accessing any of the .pfx certificates
if ($errorCount -gt 0) {
    $hostName = (Get-WmiObject win32_computersystem).DNSHostName + "." + (Get-WmiObject win32_computersystem).Domain
    $msgBody = "Please chack the logs at $($logFile) on $($hostName), the ACME Cert Report script is experiencing issues."
    sendEmailFromHost -to $msgTo -body $msgBody -subject $msgSubject -smtpServer $msgSmtpServer
    exit(1)
}

# Sort certificates by closest expiration date
$expiringCertificates = $expiringCertificates | Sort-Object -Property NotAfter

# Generate and format the HTML report and check if there are any expiring certificates before sending the email
if ($expiringCertificates.Count -gt 0) {
    $msgBody = "<html><head><style>"
    $msgBody += "BODY{background-color:white;}"
    $msgBody += "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
    $msgBody += "TH{border-width: 1px;padding: 5px;border-style: solid;border-color: black;foreground-color: black;background-color: LightBlue}"
    $msgBody += "TD{border-width: 1px;padding: 5px;border-style: solid;border-color: black;foreground-color: black;background-color: white}"
    $msgBody += "</style>"
    $msgBody += "<html><body><h2>Certificates expiring in the next $($expiryThreshold) days </h2>"
    $msgBody += "<table><tr><th>Subject</th><th>Thumbprint</th><th>DNS Names</th><th>Expiry Date</th></tr>"

    # Format lines for each expiring certificate in the report
    foreach ($cert in $expiringCertificates) {
        $subject = $cert.Subject -replace 'CN=([^,]+).*', '$1'  # Extract Common Name from the subject
        $expiryDate = $cert.NotAfter.ToString("MM/dd/yyyy")     # Slice time off of expiration date
        $dnsNames = $cert.DnsNameList -join "<br>"              # List Subject Alternative DNS names
        $msgBody += "<tr><td>$subject</td><td>$($cert.Thumbprint)</td><td>$dnsNames</td><td>$expiryDate</td></tr>"
    }
    $msgBody += "</table></body></html>"
    
    # Send Email
    sendEmailFromHost -to $msgTo -body $msgBody -subject $msgSubject -smtpServer $msgSmtpServer -bodyAsHtml
    Write-Output ("$($date) - SUCCESS - Script ran successfully, email sent") | Out-File -FilePath $logFile -Append
}
else {
    Write-Output ("$($date) - SUCCESS - No certifcates expiring in next $($expiryThreshold) days") | Out-File -FilePath $logFile -Append
}
exit(0)
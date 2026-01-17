Overview

The Windows Certbot implementation uses the Certbot installation to automatically renew certificates.  The certificates are setup on the inCommon side of things to use the ACME protocol for renewal.  When you install Certbot it creates a scheduled task automatically and checks for certificates everyday.  It will generate a new certificate and put it in the certbot live directory once the expiration threshold (14 Days is reached.)

The AcmePublisher script then checks the certbot live directory for new certificates and publishes a new .pfx file to the ‘Certbot Certificates’ Share if a new certificate is detected.  It will also update the EIP calendar with an event for the due date of the new certificate.

The new certificates still need to be imported manually from the share to the computer certificate store for the system for which the cert is to be used on.

acmeCertReport.ps1:

This script  checks a directory for .pfx certificate files.  If there are any certificates expiring within the amount of days specified in the $expiryThreshold variable, an HTML email report is sent off to the recipients configured in $msgTo.  The script also relies on Powershell 7 and OpenSSL 1.1.1.  Powershell 7 is required for the necessary PFX modules.  OpenSSL 1.1.1 is required for interoperability of PFX certificates between the Windows Server 2016 operating system and greater.  The secret.encrypted file used to set the PFX PW must be generated before executing the script.  The Client Secret JSON file for the Google Cloud Project associated with the app used to post to the calendar event must also be in the same directory as this script.

AcmePublisher.ps1:

This script works with the windows Certbot 1.24.0 install to create a .pfx certificate if a new certificate is detected in the Certbot live directory.  It relies on the current in use .pfx certificate for a system to be located in the PfxShareDir directory.  The name must match the corresponding sub-directory for the certificate in the Certbot live directory. The script will extract the thumbprint for all the .pfx certificates in the PfxShareDir directory and compare it with the thumbprint of the corresponding certificate in the CertbotLiveDir directory.  If a new certificate is detected in the CertbotLiveDir directory, the .pfx file for the new certificate is created and placed in the PfxShareDir.  The expiring .pfx certificate is placed in the PfxArchiveDir directory and has the expiration date appended to the filename.  A google calendar event is also created and posted to the designated google calendar for the expiration of the new certificate.  The CalendarNoticeDays variable is set to a negative number for the amount of days warning desired for the calendar event.

This script also relies on Powershell 7 and OpenSSL 1.1.1.  Powershell 7 is required for the necessary PFX modules.  OpenSSL 1.1.1 is required for interoperability of PFX certificates between the Windows Server 2016 operating system and greater.  The secret.encrypted file used to set the PFX PW must be generated before running the script.  The Client Secret JSON file for the Google Cloud Project associated with the app used to post to the calendar event must also be in the same directory as this script.
Run GetGoogleRefreshToken.ps1 first to add the refresh token to the Client Secret JSON file before running this script.
Certbot Publish New PFX.xml & Certbot Upcoming Renewal Report.xml:
XML files that can be imported as scheduled tasks to run the scripts.

GetGoogleRefreshToken.ps1:

This script requires an existing GCP project with the associated Google API and OAuth 2.0 Client IDs enabled.  It takes the Client ID JSON file and requests a refresh token.  It then adds/updates the refresh_token as a property in the JSON file so that it can be used by other scripts to obtain an access token and call the API.  The process of obtaining a refresh token opens up a browser window and prompts you for user consent.  Once consent is granted the browser then provides an access code that is input into the terminal running the script.

Third Party Packages:

Downloads for a few of the packages required to run these scripts.

Setup Instructions:
1)
Setup a service account in Active Directory.
The certbot live directory uses symbolic links to secure files.  You do not appear to be able to delegate permissions to them. Assign the service account as a local admin.

In order to execute the AcmePublisher.ps1 script correctly you will need to setup a secure credentials file.

You have to login locally as the service account user and run the below command in PowerShell ISE as Admin. The PowerShell 7 console does not work because it cannot generate the popup to input the PW

Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File -FilePath "C:\Certbot\secret.encrypted"

2)
Create a shared folder for the .pfx certificates and lock it down with the appropriate permissions.

Share Permissions: Gave local admins, and Domain Admins full control of the share in the share permissions.   The service account gets modify.

NTFS permissions: local admins and Domain Admins get full control and  the service account gets modify

3)
Download and install the packages in the ‘Third Part Packages’ folder within this repo.

Do not allow PowerShell remoting.

Do not allow updates via Microsoft Update or WSUS.  We don’t want any unexpected package break updates.

Update the Path System Environment Variable to only have the 1.1.1 install’s folder path available for openssl
C:\Program Files\OpenSSL-Win64\bin

*The Certbot package was originally downloaded form the below link
https://dl.eff.org/certbot-beta-installer-win32.exe

4)
You will also need to grab the client secret JSON file required to run the GetGoogleRefreshToken.ps1

The repo for GetGoogleRefreshToken.ps1 has those instructions
https://github.com/yourorg/powershell-publish-google-calendar-event

5)
Implement a certificate

Login at https://cert-manager.com/customer/InCommon?locale=en#ssl_certificates  Scroll over to the Enrollment dropdown on the left and select ACME.

Check the box for the https://acme.sectigo.com/v2/InCommonRSAOV endpoint and click on accounts at the top

Click the plus sign on the upper right to create a new account under the endpoint

Use the FQDN for the name

Add the applicable domains

Grab the keys and input them in the below command.  Execute the command on the system with Certbot installed.  You will need to do it from a normal Command Prompt as Administrator
certbot certonly --standalone --non-interactive --agree-tos --email username@org.edu --server https://acme.sectigo.com/v2/InCommonRSAOV --eab-kid <Key ID> --eab-hmac-key <HMAC Key> --domain dnsname1,dnsname2,dnsname3 --cert-name hostname -v

You can now generate the .PFX file from the .pem file for the certificate in the Certbot Live directory.  Here is an example of that command.
openssl pkcs12 -export -in "C:\Certbot\live\hostname\cert.pem" -inkey "C:\Certbot\live\hostname\privkey.pem" -out "D:\Certbot Certifcates\hostname.pfx" -password pass:<Service Account PW>

---

## Third-Party Dependencies

This project uses the following third-party tools and libraries:

- **Certbot** (Apache-2.0 License) - Automated certificate management tool by the Electronic Frontier Foundation (EFF)
- **OpenSSL 1.1.1** (Apache-2.0 License / OpenSSL License) - Cryptographic library and SSL/TLS toolkit
- **PowerShell 7** (MIT License) - Cross-platform PowerShell runtime
- **Google Calendar API** - Google API for calendar event management (proprietary, subject to Google's Terms of Service)

Please refer to each tool's license for specific terms and conditions. Certbot is available from: https://certbot.eff.org/
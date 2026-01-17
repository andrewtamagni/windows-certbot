# This script requires an existing GCP project with the associated Google API and OAuth 2.0 Client IDs enabled.
# It takes the Client ID JSON file and requests a refresh token.  It then adds/updates the refresh_token 
# as a property in the JSON file so that it can be used by other scripts to obtain an access token and call
# the API.  The process of obtaining a refresh token opens up a browser window and prompts you for user consent.
# Once consent is granted the browser then provides an access code that is input into the terminal running the
# script.

# Set variable for client_secret.json path
$clientSecretJsonFile = "$PSScriptRoot\client_secret.json"

# Import client_secret.json as object
$clientSecretJson = Get-Content -Raw -Path $clientSecretJsonFile | ConvertFrom-Json

# Extract client_id and client_secret from client_secret.json
$clientId = $clientSecretJson.installed.client_id
$clientSecret = $clientSecretJson.installed.client_secret

# Set the authorized scopes for the APIs being used.
$scopes = "https://www.googleapis.com/auth/calendar", "https://www.googleapis.com/auth/calendar.events"

# Make a call to the Google API to authorize consent.  This will create a browser popup and require login.
Start-Process "https://accounts.google.com/o/oauth2/v2/auth?client_id=$clientId&scope=$([string]::Join("%20", $scopes))&access_type=offline&response_type=code&redirect_uri=urn:ietf:wg:oauth:2.0:oob"    

# Prompt for authroization code obtained from broswer popup
$code = Read-Host "Please enter the code"
   
# Request and store refresh token
$response = Invoke-WebRequest https://www.googleapis.com/oauth2/v4/token -ContentType application/x-www-form-urlencoded -Method POST -Body "client_id=$clientid&client_secret=$clientSecret&redirect_uri=urn:ietf:wg:oauth:2.0:oob&code=$code&grant_type=authorization_code"
$refreshToken = ($response.Content | ConvertFrom-Json).refresh_token

# Add Refresh Token as property to JSON object and save to client_secret.json
$clientSecretJson.installed | Add-Member -NotePropertyName refresh_token -NotePropertyValue $refreshToken -Force
$clientSecretJson | ConvertTo-Json | Set-Content $PSScriptRoot"\client_secret.json"
# #These are the needed parameters for making the correct api call to the correct ADO org
param (
    [Parameter(Mandatory=$true)]
    [string]$organization,

    [Parameter(Mandatory=$true)]
    [string]$project
)

#This section will create an ADO ticket through an api call
#$this is my change

function createWorkTicket {
    param (
      $op,
      $titlePath,
      $from,
      $title,
      $descriptionPath,
      $description
    )

    $pat = "2v3yyoe4fur6cvzygsq4mriyzkljvyfsx2th2pgoxs5y2mlnefia"
    $credential = [System.Management.Automation.PSCredential]::new("PlaceHolder", (ConvertTo-SecureString -String $pat -AsPlainText -Force))
    $uri = "https://dev.azure.com/$organization/$project/_apis/wit/workitems/`$Issue?api-version=7.1-preview.3"


    $headerParams = @{
        "Content-Type" = "application/json-patch+json"
        "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($credential.UserName + ":" + $credential.GetNetworkCredential().Password))
    }

    $bodyTitle = @{
        op = $op
        path = $titlePath
        from = $from
        value = $title
    }

    $bodyDescription = @{
      op = $op
      path = $descriptionPath
      from = $from
      value = $description
    }

    $body = @($bodyTitle, $bodyDescription) | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $uri -Method 'POST' -Headers $headerParams -Body $body
    write-host $response
}

#______________________________________________________________________________________________________________________________________________________________________

#This will grab the access token
function getAccessToken {
    #This is the authentication URI - this will give us the token to make our calls
    $uri = "https://daikinapplied.checkmarx.net/cxrestapi/auth/identity/connect/token"

    #body params as hashtable
    $bodyParams = @{
        username = "adoscanning" #admin account for cx - find a way to sanitize this
        password = "n?1Px5(nYGH<TFjI<.I11!I7E4x" #password for account - find a way to sanitize this
        grant_type = "password"
        scope = "access_control_api sast_api"
        client_id = "resource_owner_sast_client"
        client_secret = "014DF517-39D1-4453-B7B3-9930C563627C"
    }

    #send post request
    $response = Invoke-RestMethod -Uri $uri -Method Post -Body $bodyParams -ContentType "application/x-www-form-urlencoded"

    #this is our access token needed for making API requests
    $accessToken = $response.access_token

    return $accessToken
}

$accessToken = getAccessToken

#using our accessToken we will get the scanID of the latest scan - this will help us grab the most current scan - this will be run right after a scan is generated making sure we grab the most recent
function getScanID {
    #this is the URI which hits the api for most current scan - special note on last-1
    $uri = "https://daikinapplied.checkmarx.net/cxrestapi/sast/scans?last=1"

    #header params as a hashtable
    $headerParams = @{
        Authorization = "Bearer $accessToken"
        Accept = "application/json;v=1.0"
    }

    #response grabs the scan ID then we return it on line 41
    $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headerParams

    return $response.id
}

$scanID = getScanID

#this will create a report ID - this report ID will allow us to create a future CSV with full scan results 
function createReportID {
    #this is the uri to hit the api that creates a reportID
    $uri = "https://daikinapplied.checkmarx.net/cxrestapi/reports/sastScan"

    $headerParams = @{
        Authorization = "Bearer $accessToken"
        Accept = "application/json;v=1.0"
    }

    $bodyParams = @{
        reportType = "xml"
        scanId = $scanID
    }

    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headerParams -Body $bodyParams

    #No idea why I have to do -1 here - but its almost like the call of getCSVReport is finishing before this one
    #By adding this I think I get the right report - could not tell you why though. It also only sends in XML
    return $response.reportID - 1
}

$reportID = createReportID

function getXMLReport {
    $uri = "https://daikinapplied.checkmarx.net/cxrestapi/reports/sastScan/$reportID"

    $headerParams = @{
        Authorization = "Bearer $accessToken"
        Accept = "application/json;v=1.0"
    }

    $response = Invoke-RestMethod -Uri $uri -Headers $headerParams -Method Get -ContentType "application/xml"

    $response = $response -replace "ï»¿", ""

    if ($response) {
        try {
            $response | Out-File -FilePath "C:\Users\odellkc\File6.xml"
            Write-Host "XML report saved to $OutputPath"
        } catch {
            Write-Host "Error saving the XML report to a file: C:\Users\odellkc\File.xml"
        }
    } else {
        Write-Host "No response received from the API."
    }
}


getXMLReport

#_________________________________________________________________________________

# This section will be gathering the infor for the Work Ticket in Azure - then calling the function to write it

[xml]$xmlData = Get-Content -Path "C:\Users\odellkc\File6.xml"

$queries = $xmlData.DocumentElement.Query



foreach ($query in $queries) {
    $title = $query.name
    $severity = $query.Severity
    if ($query.Result.length -ne 1) {
        foreach($result in $query.Result) {
            $file = $result.FileName
            $link = $result.DeepLink
    
            $description = "
            Vulnerability: $title
            Severity: $severity
            File Name: $file
            
            Details: $link
            "

            createWorkTicket -op "add" -titlePath "/fields/System.Title" -from $null -title "$title || Severity: $severity" -descriptionPath “/fields/System.Description” -description $description
        }
    } else {
        $file = $query.Result.FileName
        $link = $query.Result.DeepLink

        $description = "
        <div>Vulnerability: $title</div>
        <div>Severity: $severity</div>
        <div>File_Name: $file</div>
        <br>
        <div>Details: <a href=`"$link`">$link</a></div>
        "

        createWorkTicket -op "add" -titlePath "/fields/System.Title" -from $null -title "$title || Severity: $severity" -descriptionPath “/fields/System.Description” -description $description
    }
}

# ______________________________________________________________________________________________





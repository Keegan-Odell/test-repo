#These are the needed parameters for making the correct api call to the correct ADO org
param (
    [Parameter(Mandatory = $true)]
    [string]$organization,

    [Parameter(Mandatory = $true)]
    [string]$project,

    [Parameter(Mandatory = $true)]
    [string]$projectName
)
#_________________________________________________________________________________________________________________________________

#This section will create an ADO ticket through an api call
function createWorkTicket {

    #This is the list of parameters needed when making a ticket
    param (
        $op,
        $titlePath,
        $from,
        $title,
        $descriptionPath,
        $description
    )


    $pat = "yr4mzdmw6tkt3gwztzvqwjekpjqp2vdrg2atdrf4fgc5kznxqtvq" #Person access token - find a way to sanitize this or change authorization
    $credential = [System.Management.Automation.PSCredential]::new("PlaceHolder", (ConvertTo-SecureString -String $pat -AsPlainText -Force)) #Basic Authorization does whatever this is
    $uri = "https://dev.azure.com/$organization/$project/_apis/wit/workitems/`$Issue?api-version=7.1-preview.3" #API endpoint
    
    #This is the header needed to make the call
    $headerParams = @{
        "Content-Type"  = "application/json-patch+json"
        "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($credential.UserName + ":" + $credential.GetNetworkCredential().Password))
    }
    
    #This is the JSON object that will make the ADO work item title
    $bodyTitle = @{
        op    = $op
        path  = $titlePath
        from  = $from
        value = $title
    }
    
    #This will be JSON object that will make the ADO work item description
    $bodyDescription = @{
        op    = $op
        path  = $descriptionPath
        from  = $from
        value = $description
    }
    
    #This is the array that we send - add other JSON objects to make the tickets more or less complicated
    $body = @($bodyTitle, $bodyDescription) | ConvertTo-Json
        
    try {
        $response = Invoke-RestMethod -Uri $uri -Method 'POST' -Headers $headerParams -Body $body
        write-host $response 
    }
    catch {
        Write-Host "There was an Error with the ADO Work Item API"
    }
}

#______________________________________________________________________________________________________________________________________________________________________

#This will grab the access token
function getAccessToken {
    #This is the authentication URI - this will give us the token to make our calls
    $uri = "https://daikinapplied.checkmarx.net/cxrestapi/auth/identity/connect/token"

    #body params as hashtable
    $bodyParams = @{
        username      = "adoscanning" #admin account for cx - find a way to sanitize this
        password      = "n?1Px5(nYGH<TFjI<.I11!I7E4x" #password for account - find a way to sanitize this
        grant_type    = "password"
        scope         = "access_control_api sast_api"
        client_id     = "resource_owner_sast_client"
        client_secret = "014DF517-39D1-4453-B7B3-9930C563627C"
    }

    #send post request
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $bodyParams -ContentType "application/x-www-form-urlencoded"
    }
    catch {
        Write-Host "There was an error creating the Access Token for Checkmarx" #Error message
        Exit 1 #This completely stops the code from running
    }

    #this is our access token needed for making API requests
    $accessToken = $response.access_token

    return $accessToken
}

#We then assign this access token to a variable we will use in the CX Apis for validation
$accessToken = getAccessToken

#using our accessToken we will get the scanID of the latest scan - this will help us grab the most current scan - this will be run right after a scan is generated making sure we grab the most recent
function getScanID {
    $num = 1
    while ($true) {
        #this is the URI which hits the api scans - we loop through the api until we hit the scan which matches our pipelines given scan - we find the most current scan and only go to 10 to prevent an endless loop
        $uri = "https://daikinapplied.checkmarx.net/cxrestapi/sast/scans?last=$num"
    
        #header params as a hashtable
        $headerParams = @{
            Authorization = "Bearer $accessToken"
            Accept        = "application/json;v=1.0"
        }

        #response grabs the scan ID
        try {
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headerParams
            write-host $num
        }
        catch {
            Write-Host "There was a problem retrieving the Scan ID"
            Exit 1
        }

        #We check if this is the project we are looking for by comparing it to the variable in the pipeline
        if($response[$num - 1].project.name -eq $projectName) {
            #We return the response id
            return $response[$num - 1].id
        } 

        #this is to prevent a super long loop. If there is a problem we shutdown and ask the user to try again
        if ($num -gt 9) {
            Write-Host "There was a problem retrieving the Scan ID - please check the given project name"
            Exit 1
        }

        $num++
    }
}

#We assign the scanID to this variable 
$scanID = getScanID

#this will create a report ID - this report ID will allow us to create a future CSV with full scan results 
function createReportID {
    #this is the uri to hit the api that creates a reportID
    $uri = "https://daikinapplied.checkmarx.net/cxrestapi/reports/sastScan"

    #header params needed to make the api call
    $headerParams = @{
        Authorization = "Bearer $accessToken"
        Accept        = "application/json;v=1.0"
    }

    # body params needed to make the api call
    $bodyParams = @{
        reportType = "xml"
        scanId     = $scanID
    }

    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headerParams -Body $bodyParams

    #No idea why I have to do -1 here - but its almost like the call of getCSVReport is finishing before this one
    #By adding this I think I get the right report - could not tell you why though. It also only sends in XML
    #any ideas on how to not subtract one let me know - the app is still working as intended though - it grabs the most current report
    return $response.reportID - 1
}

#create the reportID used to get the xml report
$reportID = createReportID

function getXMLReport {
    #This is to get the XML report
    $uri = "https://daikinapplied.checkmarx.net/cxrestapi/reports/sastScan/$reportID"

    #headers needed to get the xml report
    $headerParams = @{
        Authorization = "Bearer $accessToken"
        Accept        = "application/json;v=1.0"
    }

    #this is the response when we hit that API
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headerParams -Method Get -ContentType "application/xml"
    }
    catch {
        Write-Host "No response received from the API."
    }
    

    #This is to santizie the response and remove the beginning characters which prevent the creation of an XML file
    $response = $response -replace "ï»¿", ""


    #This returns our sanitized response that we can pair to a variable
    return $response
}


#_________________________________________________________________________________

# This section will be gathering the info for the Work Ticket in Azure - then calling the function to write it

#This sets our xmlResponse to the xmlData variable and we make sure it is in xml format with the [xml] tag
[xml]$xmlData = getXMLReport

#This is the base that we will use to navigate inside our XML file - returns an array of queries for each issue
$queries = $xmlData.DocumentElement.Query


#for each query inside of our queries we gather the title, severity, file, and link to make our ticket - we then call our makeTicket function to create the tickets
foreach ($query in $queries) {
    $title = $query.name
    $severity = $query.Severity
    if ($query.Result.length -ne 1) { #If this particular query has more than 1 result that means the vunerability exists multipe time in the code - we will make a ticket for each instance 
        foreach ($result in $query.Result) {
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
    }
    else {
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





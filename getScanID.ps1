function grabScanId {
    # Constructing the path to the file within the agent's directory
    $filePath = "\a\1"  # Adjust the path as needed

    # Retrieve a specific JSON file within the directory
    $jsonFiles = Get-ChildItem -Path $filePath -Filter *.json  # Replace *.json with the specific file name if needed
    
    if ($jsonFiles.Count -gt 0) {
        $specificJsonFile = $jsonFiles[0].FullName  # Assuming you want the first file found
        $jsonObject = Get-Content -Path $specificJsonFile -Raw | ConvertFrom-Json
        return $jsonObject
    } else {
        Write-Output "No JSON file found in the directory: $filePath"
    }
}

# Call the function and assign the output to the $JsonObject variable
$JsonObject = grabScanId
$scanID = $JsonObject.scan


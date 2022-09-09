#region send data to log analytics
Function Send-LogAnalyticsData {
	<#
   .SYNOPSIS
	   Send log data to Azure Monitor by using the HTTP Data Collector API

   .DESCRIPTION
	   Send log data to Azure Monitor by using the HTTP Data Collector API

   .NOTES
	   Author:      Jan Ketil Skanke
	   Contact:     @JankeSkanke
	   Created:     2022-01-14
	   Updated:     2022-01-14

	   Version history:
	   1.0.0 - (2022-01-14) Function created
   #>
   param(
		[string]$WorkspaceId,
   		[string]$WorkspaceKey,
		[array]$Body,
		[string]$LogType

   )
   #Defining method and datatypes
   $method = "POST"
   $contentType = "application/json"
   $resource = "/api/logs"
   $date = [DateTime]::UtcNow.ToString("r")
   $contentLength = $Body.Length
   #Construct authorization signature
   $xHeaders = "x-ms-date:" + $date
   $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
   $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
   $keyBytes = [Convert]::FromBase64String($WorkspaceKey)
   $sha256 = New-Object System.Security.Cryptography.HMACSHA256
   $sha256.Key = $keyBytes
   $calculatedHash = $sha256.ComputeHash($bytesToHash)
   $encodedHash = [Convert]::ToBase64String($calculatedHash)
   $signature = 'SharedKey {0}:{1}' -f $WorkspaceId, $encodedHash

   #Construct uri
   $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

   #validate that payload data does not exceed limits
   if ($Body.Length -gt (31.9 *1024*1024))
   {
	   throw("Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($Body.Length/1024/1024).ToString("#.#") + "Mb")
   }
   $payloadsize = ("Upload payload size is " + ($Body.Length/1024).ToString("#.#") + "Kb ")

   #Create authorization Header
   $headers = @{
	   "Authorization"        = $signature;
	   "Log-Type"             = $LogType;
	   "x-ms-date"            = $date;
	   "time-generated-field" = $TimeStampField;
   }
   #Sending data to log analytics
   $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $Body -UseBasicParsing
   $statusmessage = "$($response.StatusCode) : $($payloadsize)"
   return $statusmessage
}
#endregion

# Example script to handle api call to AI in this example we are using
# ChatGPT 4.1 Mini, We also store the response in the store variable
# which can be loaded/accesed in the next script
#------------------------------------------------------------------

# Please replace the API key with your own
$apiKey = "sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Check if template API key is used
if ($apiKey -like "sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX") {
    Write-Host "<WRITE-LOG = ""*Please replace the API key!*"">"
    Write-Error "Please replace the API key!"
}

# Please replace the API URL with your own if not OpenAI
$url = "https://api.openai.com/v1/chat/completions"

# Please enter desired API model 
$model = "gpt-4.1-mini"

# Please enter your prompt as text
$askAI = "Explain AI in 100 words"

#--------------------------------------------------------------------

#API Call
$headers = @{
    "Authorization" = "Bearer $apiKey"
    "Content-Type" = "application/json"
}

$body = @{
    "model" = "$model"
    "messages" = @(
        @{ "role" = "user"; "content" = "$askAI" }
    )
} | ConvertTo-Json -Depth 5

# Store response in variable
$response = (Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body).choices[0].message.content

# Output response
Write-Host "AI Response: $response"

#--------------------------------------------------------------------
# Store text or variables to parse data to the next script
$store = "AI Response: $result"

#--------------------------------------------------------------------

# ServerEngine can handle system reboot cycles 
# and seemlesy continue the next scripts when using Runbooks. 
# ServerEngine initiates a waiting sequence and after
# successfull reconnection the cycle ends
#-------------------------------------------------

# Use this specific line for successfully reboot cycles
Invoke-Command { Start-Sleep 3;Write-Host " ""State : Reboot"" ";Restart-Computer -Force }; Exit-PSSession 


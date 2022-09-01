Chkdsk /f
sfc /scannow
DISM /online /Cleanup-Image /StartComponentCleanup
DISM /online /Cleanup-Image /StartComponentCleanup /ResetBase

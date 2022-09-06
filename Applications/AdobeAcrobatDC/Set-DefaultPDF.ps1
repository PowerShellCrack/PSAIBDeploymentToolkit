switch ((Get-CimInstance -ClassName Win32_OperatingSystem).Version) {
    # 1511
    10.0.10586 { $edgeID = 'AppX7rm9drdg8sk7vqndwj3sdjw11x96jc0y' }
    # 1607, 1703, 1709 and 1803
    Default { $edgeID = 'AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723' }
}

$defaults = "$env:SystemDrive\Windows\System32\OEMDefaultAssociations.xml"
[xml]$xml = Get-Content -Path $filepath
$pdfAssoc = $xml.DefaultAssociations.Association | ? {$_.Identifier -eq ".pdf"}
$pdfAssoc.ProgID = "AcroExch.Document.DC"
$pdfAssoc.ApplicationName = "Adobe Acrobat Reader DC"
if (!($pdfAssoc.OverWriteIfProgIdIs)) {
    $attrib = $pdfAssoc.OwnerDocument.CreateAttribute("OverWriteIfProgIdIs")
    $attrib.Value = "$edgeID"
    $pdfAssoc.Attributes.Append($attrib)
if ($pdfAssoc.OverwriteIfProgIdIs -notmatch $edgeID) {
    $pdfAssoc.OverwriteIfProgIdIs = "$edgeID;$($pdfAssoc.OverWriteIfProgIdIs)"
}
$xml.save($defaults)
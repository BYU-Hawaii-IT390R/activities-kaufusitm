$vm   = "IT390R-Win10"
$iso  = "C:\ISOFiles\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$ans  = "$PSScriptRoot\answer.iso"
$disk = "$env:TEMP\Win10-$env:USERNAME.vdi"

# 1  Clean up older run
& VBoxManage unregistervm $vm --delete 2>$null
Remove-Item $disk -Force -ea 0

# 2  Create fresh VM
& VBoxManage createvm --name $vm --ostype Windows10_64 --register
& VBoxManage modifyvm $vm --memory 3072 --cpus 2 --ioapic on --boot1 dvd
& VBoxManage createhd --filename $disk --size 40000 --variant Standard
& VBoxManage storagectl $vm --add sata --name "SATA"
& VBoxManage storageattach $vm --storagectl "SATA" --port 0 --type hdd     --medium $disk
& VBoxManage storageattach $vm --storagectl "SATA" --port 1 --type dvddrive --medium $iso
& VBoxManage storageattach $vm --storagectl "SATA" --port 2 --type dvddrive --medium $ans

# 3  Boot headless
& VBoxManage startvm $vm --type headless
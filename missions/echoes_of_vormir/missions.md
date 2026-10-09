# Echoes of Vormir

Vormir remembers.

Something happened on a Windows machine before its memory was captured.

The evidence is scattered, and not everything left behind is what it seems.

Begin by understanding the memory you've been given. Then follow the traces left behind by the expedition.

Five artifacts remain.

The expedition ends when the final record is found.

The file is soul.mem that was too big to fit in the repo.

Note: You will be using same file through out the mission

Flag format: OWASP{...}


This is a group of missions, from Mem-1 to Mem-6, I didn't succeed in all of it but there is some of them here.


## Mem-1 : When It Happened

We installed Volatility3 from GitHub and then first launched `windows.info.Info` to see the date and if it was really a windows ram dump :
```bash
volatility3 -f /path/soul.mem windows.info.Info
```
Here is the flag : OWASP{2026-10-08 05:07:43}



Mem-2 : Soul Hunt

We launch windows.pslist.PsList to search for all the processus :
```bash
volatility3 -f /path/soul.mem windows.pslist.PsList
...
4220	896	RuntimeBroker.	0xdb0f78f7f080	2	-	1	False	2026-10-08 04:43:39.000000 UTC	N/A	Disabled
2580	6960	SoulHunt_7F31.	0xdb0f78242080	8	-	1	False	2026-10-08 04:48:01.000000 UTC	N/A	Disabled
8348	2580	conhost.exe	0xdb0f7808b080	3	-	1	False	2026-10-08 04:48:01.000000 UTC	N/A	Disabled
...
```
The flag is : OWASP{SoulHunt_7F31}



Mem-3 : The Painted Soul

I did Mem-4 and Mem-6 before while searching for this answer and I found out that there is Paint launched with Vormir.png and I have to extract the data from paint to convert it into an image and then find the flag.

volatility3 -f /home/itadown/Documents/cyberSecurity/byteme/missions/soul.mem -o .  windows.memmap.Memmap --pid 1204 --dump > paint-memmap.txt

And I did some settings, RGB 32-bits, big endian, 1920x1080 and found an hexa that was reversed to find out : 
4f574153507b736 f756c73746f6e65 5f7061696e745f3 736e655f3

And this was the first part of the flag that I found:
OWASP{soulstone_paint_

I didn't found the rest of this part so I will see writeups.



Now we need to see if here is other related files :

volatility3 -f /path/soul.mem windows.pstree.PsTree | grep -iC 10 "SoulHunt_7F31.exe"
***** 5524 100.06332	msedge.exeB scan0xdb0f77183080  9       -       1       False	2026-10-07 21:24:06.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=on_device_model.mojom.OnDeviceModelService --lang=en-US --service-sandbox-type=on_device_model_execution --ram-no-pressure-read-main-dll --metrics-shmem-handle=1484,i,4544997038133453204,1449394686480856198,524288 --field-trial-handle=2384,i,5999762545274054880,2006447652457690792,262144 --variations-seed-version --pseudonymization-salt-handle=2388,i,648376459080735042,4526222118194120183,4 --trace-process-track-uuid=3190708995682289984 --mojo-platform-channel-handle=2584 /prefetch:8	C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
***** 7092	6332	msedge.exe	0xdb0f782b9080	13	-	1	False	2026-10-07 21:21:04.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=gpu-process --gpu-recent-crash-count=0 --gpu-preferences=WAAAAAAAAADgAAAEAAAAAAAAAAAAAGAAQAAAAAAAAAADAAAAAAAAADgAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAoAAAAAAAAAAgAAAAAAAAAEAAAAAIAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAA= --startup-read-main-dll --metrics-shmem-handle=2252,i,260848751405262724,13379942365060081537,262144 --field-trial-handle=2384,i,5999762545274054880,2006447652457690792,262144 --variations-seed-version --pseudonymization-salt-handle=2388,i,648376459080735042,4526222118194120183,4 --trace-process-track-uuid=3190708988185955192 --mojo-platform-channel-handle=2380 /prefetch:2	C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
***** 8760	6332	msedge.exe	0xdb0f71c72080	17	-	1	False	2026-10-07 21:27:56.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --pdf-upsell-enabled --disable-gpu-compositing --video-capture-use-gpu-memory-buffer --lang=en-US --js-flags --device-scale-factor=1 --num-raster-threads=3 --enable-main-frame-before-activation --renderer-client-id=19 --skip-read-main-dll --launch-time-ticks=464271324 --metrics-shmem-handle=7136,i,420041924823593761,1320084627393558238,1048576 --field-trial-handle=2384,i,5999762545274054880,2006447652457690792,262144 --variations-seed-version --pseudonymization-salt-handle=2388,i,648376459080735042,4526222118194120183,4 --trace-process-track-uuid=3190709004115666625 --mojo-platform-channel-handle=7016 /prefetch:1	C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
***** 7100	6332	msedge.exe	0xdb0f782b4080	19	-	1	False	2026-10-07 21:21:04.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --startup-read-main-dll --metrics-shmem-handle=2320,i,13176200713304972554,10956372942577150175,524288 --field-trial-handle=2384,i,5999762545274054880,2006447652457690792,262144 --variations-seed-version --pseudonymization-salt-handle=2388,i,648376459080735042,4526222118194120183,4 --trace-process-track-uuid=3190708989122997041 --mojo-platform-channel-handle=2612 /prefetch:3	C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
*** 5384	2416	SecurityHealth	0xdb0f77e81080	1	-	1	False	2026-10-07 21:20:55.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\SecurityHealthSystray.exe	"C:\Windows\System32\SecurityHealthSystray.exe" 	C:\Windows\System32\SecurityHealthSystray.exe
*** 2024	2416	OneDrive.exe	0xdb0f72448080	16	-	1	False	2026-10-07 21:20:56.000000 UTC	N/A	\Device\HarddiskVolume1\Users\nightwatch\AppData\Local\Microsoft\OneDrive\OneDrive.exe	"C:\Users\nightwatch\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background	C:\Users\nightwatch\AppData\Local\Microsoft\OneDrive\OneDrive.exe
*** 2252	2416	VBoxTray.exe	0xdb0f77e8c080	11	-	1	False	2026-10-07 21:20:55.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\VBoxTray.exe	"C:\Windows\System32\VBoxTray.exe" 	C:\Windows\System32\VBoxTray.exe
*** 6960	2416	powershell.exe	0xdb0f78562340	10	-	1	False	2026-10-07 21:21:11.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\WindowsPowerShell\v1.0\powershell.exe	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
**** 6624	6960	conhost.exe	0xdb0f78566080	3	-	1	False	2026-10-07 21:21:12.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4	C:\Windows\system32\conhost.exe
**** 4968	6960	notepad.exe	0xdb0f76e94080	1	-	1	False	2026-10-07 21:24:17.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\notepad.exe	"C:\Windows\system32\notepad.exe" C:\Users\nightwatch\Documents\Vormir\expedition.txt 	C:\Windows\system32\notepad.exe
**** 2580	6960	SoulHunt_7F31.	0xdb0f78242080	8	-	1	False	2026-10-08 04:48:01.000000 UTC	N/A	\Device\HarddiskVolume1\Users\nightwatch\Desktop\SoulHunt_7F31.exe	"C:\Users\nightwatch\Desktop\SoulHunt_7F31.exe" -NoLogo -NoProfile -NoExit -Command Start-Sleep -Seconds 7200 	C:\Users\nightwatch\Desktop\SoulHunt_7F31.exe
***** 8348	2580	conhost.exe	0xdb0f7808b080	3	-	1	False	2026-10-08 04:48:01.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4	C:\Windows\system32\conhost.exe
*** 1204	2416	mspaint.exe	0xdb0f710b5340	3	-	1	False	2026-10-07 21:26:50.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\mspaint.exe	"C:\Windows\system32\mspaint.exe" "C:\Users\nightwatch\Pictures\Vormir.png"	C:\Windows\system32\mspaint.exe
* 8900	708	explorer.exe	0xdb0f77d6e080	69	-	1	False	2026-10-07 21:27:57.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\explorer.exe	explorer.exe	C:\Windows\explorer.exe
** 5960	8900	FTK Imager.exe	0xdb0f72d7b080	26	-	1	False	2026-10-07 21:31:32.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files\AccessData\FTK Imager\FTK Imager.exe	"C:\Program Files\AccessData\FTK Imager\FTK Imager.exe" 	C:\Program Files\AccessData\FTK Imager\FTK Imager.exe
** 4824	8900	Photos.exe	0xdb0f79027080	18	-	1	False	2026-10-08 04:54:59.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe\Photos.exe	"C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe\Photos.exe" "C:\Users\nightwatch\Pictures\Sacrifice.png"	C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe\Photos.exe
*** 2820	4824	Photos.exe	0xdb0f77fef080	13	-	1	False	2026-10-08 04:55:02.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe\Photos.exe	"C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe\Photos.exe" ms-photos:spareprocess-viewer	C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe\Photos.exe
* 924	708	fontdrvhost.ex	0xdb0f72c5d140	5	-	1	False	2026-10-07 21:20:19.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\fontdrvhost.exe	"fontdrvhost.exe"	C:\Windows\system32\fontdrvhost.exe
* 1076	708	dwm.exe	0xdb0f72d79080	20	-	1	False	2026-10-07 21:20:19.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\dwm.exe	"dwm.exe"	C:\Windows\system32\dwm.exe
1320	5756	MicrosoftEdgeU	0xdb0f783b8340	4	-	0	True	2026-10-07 21:22:27.000000 UTC	N/A	\Device\HarddiskVolume1\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe	"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c	C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe
4936	8188	MusNotifyIcon.	0xdb0f79198080	3	-	1	False	2026-10-08 03:23:34.000000 UTC	N/A	\Device\HarddiskVolume1\Windows\System32\MusNotifyIcon.exe	%systemroot%\system32\MusNotifyIcon.exe NotifyTrayIcon 19	C:\Windows\system32\MusNotifyIcon.exe

Here we can see Vormir.png and Sacrifice.png.



We need to see something so I tried to download the two pictures, first we need to retrieve the hexadecimal address :

volatility3 -f /path/soul.mem windows.filescan.FileScan | grep -i "Vormir.png"
0xdb0f77683870.0\Users\nightwatch\Pictures\Vormir.png

volatility3 -f /path/soul.mem windows.filescan.FileScan | grep -i "Sacrifice.png"
0xdb0f7a3a6b00.0\Users\nightwatch\Pictures\Sacrifice.png


Then we try to download the picture Vormir.png that returns nothing and Sacrifice.png that returns a valid picture with the flag :
volatility3 -f /path/soul.mem -o /path/ windows.dumpfiles.DumpFiles --virtaddr 0xdb0f7a3a6b00

Here is the flag from the picture (that is in this folder) :
OWASP{soulstone_memory_84c2}



Mem-6 : The Forgotten Note

Earlier we saw a file \Users\nightwatch\Documents\Vormir\expedition.txt, we need to find the hex address and then download it :

volaility3 -f /path/soul.mem windows.filescan.FileScan | grep -i "expedition.txt"
0xdb0f7a385e00.0\Users\nightwatch\Documents\Vormir\expedition.txt
volatility3 -f /path/soul.mem -o /path/ windows.dumpfiles.DumpFiles --virtaddr 0xdb0f7a385e00


Then we have a file containing this :
Artifact reference:
4f574153507b736f756c73746f6e655f6e6f74655f336339317d

Just need to decode it from hex and :
OWASP{soulstone_note_3c91}

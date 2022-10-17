### NoRunPI: Run Your Payload Without Running Your Payload


<br>
<br>

#### Since "SettingSyncHost.exe -Embedding" Runs a Thread On "SHCore.dll!Ordinal172+0x100", We can hijack the flow before this thread start, to do that :

- Load shcore.dll to calculate the thread's entry
- Create "SettingSyncHost.exe -Embedding" Process
- BruteForce the address calculated (stop when its valid)
- suspend the process
- inject the payload to the calculated address
- resume the process
- $$




### DEMO:
![image](https://user-images.githubusercontent.com/111295429/196046411-1adc092c-55a6-49bb-8cee-d12bf341296d.png)

![image](https://user-images.githubusercontent.com/111295429/196044925-4c8d3b1d-90a4-42cd-90f5-4f43e188c91e.png)


<br>
<br>

#### Note That This is An idea more than a stable poc on a process injection technique, you can find a lot of such processes (creating such threads) and implement your own code using the same way for the same results ... (for example on my machine, the same process have a thread on combase.dll!InternalTlsAllocData+0x70)

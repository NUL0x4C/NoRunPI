### NoRunPI: Run Your Payload Without Running Your Payload


<br>
<br>

#### Since "SettingSyncHost.exe -Embedding" Runs a Thread On "SHCore.dll!Ordinal172+0x100", We can hijack the flow before this thread start, to do that :

- Load shcore.dll to calculate the thread's entry
- Create "SettingSyncHost.exe -Embedding" Process
- Wait for ~ 5 ms ~ just make sure that the newly created process loads shcore.dll		[NOTE ON THIS IN THE CODE]
- suspend the process
- inject the payload to the calculated address
- resume the process
- $$




### DEMO:

![image](https://user-images.githubusercontent.com/111295429/196044925-4c8d3b1d-90a4-42cd-90f5-4f43e188c91e.png)

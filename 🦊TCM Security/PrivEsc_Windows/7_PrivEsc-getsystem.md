#Windows #PrivEsc #getsystem #msfconsole #meterpreter 

Tries to elevate the system in many ways when in `meterpreter`

```
getsystem -h
```

1. **Technique 1** creates a named pipe from Meterpreter. It also [creates and runs a service](https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/elevate/namedpipe.c) that runs _cmd.exe /c echo “some data” >\\.\pipe\[random pipe here]_. When the spawned cmd.exe connects to Meterpreter’s named pipe, Meterpreter has the opportunity to impersonate that security context. [Impersonation of clients](http://msdn.microsoft.com/en-us/library/windows/desktop/aa365573(v=vs.85).aspx) is a named pipes feature. The context of the service is SYSTEM, so when you impersonate it, you become SYSTEM.

2. **Technique 2** is like technique 1. It creates a named pipe and impersonates the security context of the first client to connect to it. To create a client with the SYSTEM user context, this technique drops a DLL to disk(!) and schedules rundll32.exe as a service to run the DLL as SYSTEM. [The DLL](https://github.com/rapid7/meterpreter/blob/master/source/elevator/namedpipeservice.c) connects to the named pipe and that’s it. Look at [elevate_via_service_namedpipe2](https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/elevate/namedpipe.c) in Meterpreter’s source to see this technique.

	As the help information states, this technique drops a file to disk. This is an opportunity for an anti-virus product to catch you. If you’re worried about anti-virus or leaving forensic evidence, I’d avoid getsystem –t 0 (which tries every technique) and I’d avoid getsystem –t 2.

3. **Technique 3** is a little different. [This technique](https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/elevate/tokendup.c) assumes you have SeDebugPrivileges—something getprivs can help with. It loops through all open services to find one that is running as SYSTEM and that you have permissions to inject into. It uses [reflective DLL injection](http://www.harmonysecurity.com/files/HS-P005_ReflectiveDllInjection.pdf) to run [its elevator.dll](https://github.com/rapid7/meterpreter/blob/master/source/elevator/tokendup.c) in the memory space of the service it finds. This technique also passes the current thread id (from Meterpreter) to elevator.dll. When run, elevator.dll gets the SYSTEM token, opens the primary thread in Meterpreter, and tries to apply the SYSTEM token to it.

**Know**:
- One runs in memory, the other in disk and ONLY run the one in memory (Technique 1).
- Can crash a machine so be careful running it

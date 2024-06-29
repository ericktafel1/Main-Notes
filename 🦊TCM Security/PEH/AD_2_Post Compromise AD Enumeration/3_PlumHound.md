#bloodhound #plumhound #neo4j
Sister to bloodhound (blue/purple team version)

To install:

Install in `/opt`:

`cd /opt`

`sudo git clone https://github.com/PlumHound/PlumHound.git`

`cd PlumHound`

`sudo pip3 install -r requirements`

Now, to run this tool, you must also follow bloodhound steps and must have neo4j console up and bloodhound up:

`sudo neo4j console`
`sudo bloodhound`

Now, PlumHound will pull down bloodhound data to analyze it. use neo4j password set in command:

A functional test:

`sudo python3 PlumHound.py --easy -p neo4j1`

```
┌─(/opt/PlumHound)────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(16:41:38)──> sudo python3 PlumHound.py --easy -p neo4j1                                                ──(Fri,Jun28)─┘

        PlumHound 1.6
        For more information: https://github.com/plumhound
        --------------------------------------
        Server: bolt://localhost:7687
        User: neo4j
        Password: *****
        Encryption: False
        Timeout: 300
        --------------------------------------
        Task: Easy
        Query Title: Domain Users
        Query Format: STDOUT
        Query Cypher: MATCH (n:User) RETURN n.name, n.displayname
        --------------------------------------
INFO    Found 1 task(s)
INFO    --------------------------------------
on 1: 
on 1: n.name                      n.displayname
      --------------------------  ---------------
      ADMINISTRATOR@MARVEL.LOCAL
      PPARKER@MARVEL.LOCAL        Peter Parker
      FCASTLE@MARVEL.LOCAL        Frank Castle
      TSTARK@MARVEL.LOCAL         Tony Stark
      SQLSERVICE@MARVEL.LOCAL     SQL Service
      KZHLRYZKCB@MARVEL.LOCAL     KzhlRYzkCb
      KRBTGT@MARVEL.LOCAL
      GUEST@MARVEL.LOCAL
      
      NT AUTHORITY@MARVEL.LOCAL
on 1: 
         Executing Tasks |██████████████████████████████████████████████████| Tasks 1 / 1  in 0.0s (4368.63/s) 

        Completed 1 of 1 tasks.
```

Default query with PlumHound:

`sudo python3 PlumHound.py -x tasks/default.tasks -p neo4j1`

```
┌─(/opt/PlumHound)────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(16:43:35)──> sudo python3 PlumHound.py -x tasks/default.tasks -p neo4j1                                ──(Fri,Jun28)─┘

        PlumHound 1.6
        For more information: https://github.com/plumhound
        --------------------------------------
        Server: bolt://localhost:7687
        User: neo4j
        Password: *****
        Encryption: False
        Timeout: 300
        --------------------------------------
        Tasks: Task File
        TaskFile: tasks/default.tasks
        Found 114 task(s)
        --------------------------------------


on 114:         Completed Reports Archive: reports//Reports.zip
         Executing Tasks |██████████████████████████████████████████████████| Tasks 114 / 114  in 3.5s (32.51/s) 

        Completed 114 of 114 tasks.

```

Zips to a report folder. To view it easily:

`cd reports`
`firefox index.html`


- know high value targets, and view them.
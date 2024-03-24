

```dataview
TABLE title, key_topics, tags, references
FROM "HTB Academy"
WHERE file.path != "HTB Academy/ExcludedFolder"
    AND file.path LIKE "HTB Academy/%"
SORT file.name ASC

```









# *NEED TO UPDATE THIS TABLE TO REFERENCE ONLY KEY COMMANDS FOR CONCEPTS... NOT FULL CHAPTERS




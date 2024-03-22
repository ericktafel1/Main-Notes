

```
TABLE title, key_topics, tags, references
FROM "HTB Academy"
WHERE file.extension = "md" AND file.name != "TEMPLATE" AND file.name != "Index"
SORT title ASC
```









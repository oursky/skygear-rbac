# Policy

Policy describes what a subject is allowed/denied to apply action on an object, and what groups a subject belongs to

**Example policy file**

```csv
p, alice, data1, read
p, bob, data2, write
p, data_group_admin, data_group, write

g, alice, data_group_admin
g2, data1, data_group
g2, data2, data_group
```

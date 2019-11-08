# Schemas

[← Back](/doc/README.md)

## Enforce policy

A enforce request consists of `subject`, `action` and `object`. 

**JSON schema:**

```json
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "subject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "meta": {
          "type": "object"
        }
      },
      "required": [
        "id",
        "type"
      ]
    },
    "action": {
      "type": "array",
      "items": [
        {
          "type": "string"
        }
      ]
    },
    "object": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "meta": {
          "type": "object"
        }
      },
      "required": [
        "id",
        "type"
      ]
    }
  },
  "required": [
    "subject",
    "action",
    "object"
  ]
}
```

**Example**
```json
{
  "subject": {
    "id": "<user-id>",
    "type": "user",
    "meta": {}
  },
  "action": ["create"],
  "object": {
    "id": "<form-id>",
    "type": "form",
    "meta": {}
  }
}
```

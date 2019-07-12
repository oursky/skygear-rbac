# System Overview

## Introduction

This system is a Skygear "gear" that carries out [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control). Given Subject + Action + Object as request, it returns whether this request is permitted according to Policy and Model.

### Terms

- Subject: Authenticated but to-be-authorized user / service
- Action: How subject want to handle object
- Object: Resource 
- Policy: List of rules of subject-action-object relations
- Model: Describes how policies are interpreted and whether to deny/allow a request

## Flow
![I/O](/doc/diagrams/input-output.svg)

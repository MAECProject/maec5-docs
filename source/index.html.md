---
title: MAEC 5 Specification Reference

language_tabs: # must be one of https://git.io/vQNgJ
  - json

toc_footers:
  - <a href='https://docs.google.com/document/d/1cnjjZAPHITFjo_8xGVBo1mX9Qvo7pN-YJ4pRZwdsuL0/'>Specification - Core Concepts</a>
  - <a href='https://docs.google.com/document/d/1btZGq2H6xtSsjrweL6NMXx7KHg6B2yIZkz9nSe6JZfA/'>Specification - Vocabularies</a>

search: true
---

# Introduction

> Sandbox analysis of a Malware Instance

```json
{
  "type":"package",
  "id":"package--773adac8-2316-42c6-6fbc-9cdef8876fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "instance_object_refs": ["0"],
        "name": {
           "value":"Zeus 1.3",
           "confidence":"medium"
        },
        "capabilities": [{"name":"anti-detection"}],
        "analysis_metadata": [
           {
              "analysis_type":"in-depth",
              "description": "ran sample through sandbox"
           }
        ]
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes":{"MD5":"4472ea40dc71e5bb701574ea215a81a1"},
        "size":25536,
        "name":"foo.dll"
     }
  }
}
```

Welcome to the Malware Attribute Enumeration and Characterization (MAEC™, pronounced “mike”) effort, a comprehensive language and data model for the exchange of malware data.

This page provides a basic outline of the MAEC 5.0 data model. For an introduction and conceptual overview of MAEC, please see the [Core Concepts](https://docs.google.com/document/d/1cnjjZAPHITFjo_8xGVBo1mX9Qvo7pN-YJ4pRZwdsuL0/) and [Vocabularies](https://docs.google.com/document/d/1btZGq2H6xtSsjrweL6NMXx7KHg6B2yIZkz9nSe6JZfA/) specification documents. There's also a [documentation website](http://maecproject.github.io/) containing examples and further information.

This documentation is divided into seven sections:

* **Top-level Objects** - MAEC top-level objects (TLOs) are the entities captured at the top level of a [Package](#Package). Examples include the Malware Instance and the Behavior Objects.

* **MAEC Types** - These MAEC 5.0 types are used by MAEC’s TLOs.

* **Relationships** - Relationships are defined between pairs of MAEC TLOs.

* **Package** - The Package is MAEC's standard output format.

* **Common Data Types** - These common data types are used by MAEC TLOs and data types.

* **Cyber Observable Object Extensions** - MAEC-specific extensions are defined for STIX Cyber Observable Objects used in the context of MAEC.

* **Vocabularies** - Many of MAEC's TLOs and data types contain properties that may be defined by MAEC open vocabularies. Each open vocabulary provides a list of common and industry-accepted terms. The use of MAEC's vocabularies is recommended to increase compatibility, but custom values may also be used.

# Top-level Objects

## Behavior

> Persistence Behavior comprising several Malware Actions:

```json
{
  "type":"package",
  "id":"package--2d42dac8-c416-42c6-bc5c-7b6dcf576fc5",
  "schema_version":"5.0",
  "maec_objects":[
    {
      "type":"behavior",
      "id":"behavior--2099d4c1-0e8a-49d2-8d32-f0427e1ff817",
      "name":"persist-after-system-reboot",
      "action_refs":[
        "malware-action--c095f1ab-0847-4d89-92ef-010e6ed39c20",
        "malware-action--80f3f63a-d5c9-4599-b9e4-2a2bd7210736"
      ],
      "attributes":{
        "persistence-scope" : "system wide"
      },
      "technique_refs":[
        {
          "source_name":"att&ck",
          "description":"registry run keys/start folder",
          "external_id":"t1060"
        }
      ]
    },
    {
      "type":"malware-action",
      "id":"malware-action--c095f1ab-0847-4d89-92ef-010e6ed39c20",
      "name":"create file",
      "output_object_refs":[
        "0"
      ]
    },
    {
      "type":"malware-action",
      "id":"malware-action--80f3f63a-d5c9-4599-b9e4-2a2bd7210736",
      "name":"create registry key value",
      "output_object_refs":[
        "1"
      ]
    }
  ],
  "observable_objects":{
    "0":{
      "type":"file",
      "hashes":{
        "MD5":"4472ea40dc71e5bb701574ea215a81a1"
      },
      "size":25536,
      "name":"foo.dll",
      "parent_directory_ref":"2"
    },
    "1":{
      "type":"windows-registry-key",
      "key":"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "values":[
        {
          "name":"Foo",
          "value":"C:\\Windows\\System32\foo.dll"
        }
      ]
    },
    "2":{
      "type":"directory",
      "path":"C:\\Windows\\System32"
    }
  }
}
```

**Type Name**: `behavior`

A Behavior corresponds to the specific purpose behind a particular snippet of code, as executed by a malware instance. Examples include keylogging, detecting a virtual machine, and installing a backdoor. Behaviors may be composed of one or more Malware Actions, thereby providing context to these Actions.

Name | Type | Description
--------- | ------- | -----------
| **id** (required) | [identifier](#identifier) | Specifies a unique ID for the Behavior.
| **type** (required) | [string](#string) | The value of property field **MUST** be `behavior`.
| **name** (required) | [open-vocab](#open-vocabulary) | Captures the name of the Behavior. The values for this property **SHOULD** come from the [behavior-ov](#behaviors) open vocabulary.|
| **description** (optional) | [string](#string) | Specifies a textual description of the Behavior.|
| **timestamp** (optional) | [timestamp](#timestamp) | Captures the local or relative time at which the Behavior occurred or was observed. |
| **action_refs** (optional) | [list](#list) of type [identifier](#identifier) | Captures Actions that serve as an implementation of the Behavior. Each list item specifies the unique ID of the Action being referenced. Each Action **MUST** be present in the current Package. The ordering of the references in the list denotes the sequential ordering of the Actions with respect to the Behavior; that is, Actions at the beginning of the list **MUST** have occurred before those later in the list.|
| **technique_refs** (optional) | [list](#list) of type [external-reference](#external-reference) | References any techniques used to implement the Behavior; for example, DLL Search Order Hijacking. Each reference **SHOULD** point to a valid [ATT&CK](https://attack.mitre.org/wiki/Main_Page) Technique or related entity.|


### Relationships

#### Embedded Relationships
Name | Valid Target(s)
---- | --------------
`action_refs` | `malware-action`

#### Common Relationships
`related-to`

#### Top-level Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| `behavior` | `dependent-on` | `behavior` | Specifies that the behavior is dependent on the successful execution of another.|
| `behavior` | `discovered-by` | `software` | Specifies that the behavior was discovered by a particular tool, as a represented by a STIX Cyber Observable Software Object. |


## Collection

> Basic Collection of Malware Instances observed together:

```json
{
  "type":"package",
  "id":"package--12fbdac8-c416-42c6-cc5c-7b84cf576fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"collection",
        "id":"collection--739df9c1-93ab-49d2-73f0-f0427e1ff817",
        "association_type":"observed together",
        "entity_refs": [
           "malware-instance--4c46cb42-8e83-4bbb-acf8-e09c1311093b",
           "malware-instance--f19859bf-26e4-415e-a1be-41c0486d406d",
           "malware-instance--4a58d70a-9d25-4c80-a114-28036705d026"
        ]
     }
  ]
}
```

**Type Name**: `collection`

A Collection captures a set of MAEC entities (e.g., Malware Instances, Behaviors, etc.) or STIX Cyber Observables that are related or associated in some way.

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The value of this property **MUST** be `collection`.
| **id** (required) | [identifier](#identifier) | Specifies a unique ID for the Collection.|
| **description** (optional) | [string](#string) | Specifies a textual description of the Collection.|
| **association_type** (optional) | [open-vocab](#open-vocabulary)| Specifies how the contents of the Collection are associated. The values for this property **SHOULD** come from the [entity-association-ov](#entity-association) vocabulary. |
| **entity_refs** (optional) | [list](#list) of type [identifier](#identifier) |Specifies a set of one or more MAEC entities that are contained in the Collection. Each item specifies the unique ID of the entity being referenced. All entities **MUST** be present in the current Package. This property is mutually exclusive with regard to the **observable_refs** property and both properties **MUST NOT** be present in the same Collection.|
| **observable_refs** (optional) | [list](#list) of type [object-ref](#object-reference) |Specifies a set of one or more STIX Cyber Observable Objects that are contained in the Collection. All Cyber Observable Objects **MUST** be present in the current Package. This property is mutually exclusive with regard to the **entity_refs** property and both properties **MUST NOT** be present in the same Collection.|

### Requirements
One of **entity_refs** or **observable_refs** **MUST** be included when using this object.

### Relationships

#### Embedded Relationships
Name | Valid Target(s)
---- | --------------
`entity_refs` | `behavior`, `collection`, `malware-action`, `malware-family`, `malware-instance`, `relationship`
`observable_refs` | `artifact`, `autonomous-system`, `directory`, `domain-name`, `email-addr`, `email-message`, `file`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `mutex`, `network-traffic`, `process`, `software`, `url`, `user-account`, `windows-registry-key`, `x509-certificate`

#### Common Relationships
`related-to`

## Malware Action

> Basic "Create File" Action

```json
{
  "type":"package",
  "id":"package--7892dac8-c416-35c6-bc5c-7b6dcf576f91",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-action",
        "id":"malware-action--c095f1ab-0847-4d89-92ef-010e6ed39c20",
        "name":"create file",
        "is_successful":true,
        "output_object_refs": ["4"],
        "timestamp": "2016-01-20T12:31:12.12345Z"
     }
  ],
  "observable_objects": {
    "4": {
       "type":"file",
       "hashes":{"MD5":"4472ea40dc71e5bb701574ea215a81a1"},
       "size":25536,
       "name":"foo.dll"
    }
  }
}
```

> Read Registry Key Value Action with Implementation

```json
{
  "type":"package",
  "id":"package--0072dac8-c416-35c6-bc5c-7b6dcf576def",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-action",
        "id":"malware-action--e754b078-4185-4eba-a06c-7b2b6c6bd0a5",
        "name":"read registry key value",
        "input_object_refs": ["3"],
        "implementation": {"api_function_name" : "RegQueryValueEx"},
        "timestamp": "2016-01-20T12:31:12.12345Z"
     }
  ],
  "observable_objects": {
     "3": {
        "type":"windows-registry-key",
        "key":"hkey_local_machine\\system\\bar\\foo",
        "values": [
           {
              "name":"Foo",
              "data":"qwerty",
              "data_type":"REG_SZ"
           }
        ]
     }
  }
}
```

**Type Name**: `malware-action`

A Malware Action represents an abstraction on a system-level API call (or similar entity) called by the malware instance during its execution, and thereby corresponds to the lowest-level dynamic operation of the malware instance. Actions do not contain any associated context as to why they were performed, as this level of detail and abstraction is documented by Behaviors. Examples of Actions include the creation of a particular file on disk and the opening of a port. Actions are commonly captured and reported by dynamic malware analysis tools (i.e., sandboxes).

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The value of this property **MUST** be `malware-action`.|
| **id** (required) | [identifier](#identifier) | Specifies a unique ID for the Malware Action.|
| **name** (required) | [open-vocab](#open-vocabulary) | Captures the name of the Malware Action. The values for this property **SHOULD** come from the [malware-action-ov](#malware-action) vocabulary.|
| **description** (optional) | [string](#string) | Captures a basic textual description of the Malware Action. |
| **is_successful** (optional) | [boolean](#boolean) | Specifies whether the Malware Action was successful in its execution. |
| **timestamp** (optional) | [timestamp](#timestamp) | Captures the local or relative time(s) at which the Malware Action occurred or was observed. |
| **input_object_refs** (optional) | [list](#list) of type [object-ref](#object-reference) |References STIX Observable Objects used as input(s) to the Malware Action. The Object(s) referenced **MUST** be specified in the **observable_objects** property of the Package.|
| **output_object_refs** (optional) | [list](#list) of type [object-ref](#object-reference) |References STIX Observable Objects resulting as output(s) from the Malware Action. The Object(s) referenced **MUST** be specified in the **observable_objects** property of the Package.|
| **api_call** (optional) | [api-call](#api-call) | Captures attributes of the specific API call that was used to implement the Malware Action. |

### Relationships

#### Embedded Relationships
Name | Valid Target(s)
---- | --------------
`input_object_refs` | `artifact`, `autonomous-system`, `directory`, `domain-name`, `email-addr`, `email-message`, `file`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `mutex`, `network-traffic`, `process`, `software`, `url`, `user-account`, `windows-registry-key`, `x509-certificate`|
`output_object_refs` | `artifact`, `autonomous-system`, `directory`, `domain-name`, `email-addr`, `email-message`, `file`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `mutex`, `network-traffic`, `process`, `software`, `url`, `user-account`, `windows-registry-key`, `x509-certificate`|

#### Common Relationships
`related-to`

#### Top-level Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| `malware-action` | `dependent-on` | `malware-action` | Specifies that the action is dependent on the successful execution of another.|
| `malware-action` | `discovered-by` | `software` | Specifies that the action was discovered by a particular tool, as a represented by a STIX Cyber Observable Software Object. |

## Malware Family

> Basic Malware Family:

```json
{
  "type":"package",
  "id":"package--f53adac8-c416-42c6-6fbc-7b6ef8876fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-family",
        "id":"malware-family--df91014d-0c2e-4e01-b8a5-d8c32bb038e6",
        "name": {
           "value":"Zeus",
           "confidence":90
        }
     }
  ]
}
```

> Expanded Malware Family:

```json
{
  "type":"package",
  "id":"package--b73adac8-3416-66c6-6fbc-096ef8876fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-family",
        "id":"malware-family--df91014d-0c2e-4e01-b8a5-d8c32bb038e6",
        "name": {
           "value":"Zeus",
           "confidence":90
        },
        "aliases": [
           {
              "value":"ZBot",
              "source":"McAfee",
              "confidence":80
           }
        ],
        "labels": ["bot", "downloader", "trojan"],
        "common_capabilities": [
           {
              "name":"persistence",
              "refined_capabilities":[{"name":"continuous execution"}]
           }
        ],
        "common_behavior_refs": ["behavior--ac15b814-868b-43fd-a89b-91e463293f2b"]
     },
     {
        "type":"malware-instance",
        "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "instance_object_refs": ["0"],
        "name": {
           "value":"Zeus 1.3",
           "confidence":80
        }
     },
     {
        "type":"behavior",
        "id":"behavior--ac15b814-868b-43fd-a89b-91e463293f2b",
        "name":"persist after system reboot"
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes": {"MD5":"4472ea40dc71e5bb701574ea215a81a1"},
        "size":25536,
        "name":"foo.dll"
     }
  },
  "relationships": [
     {
        "type":"relationship",
        "id":"relationship--74ae7da8-784d-4a00-aad1-e40c65c78b98",
        "source_ref":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "target_ref":"malware-family--df91014d-0c2e-4e01-b8a5-d8c32bb038e6",
        "relationship_type":"variant-of"
     }
  ]
}
```

**Type Name**: `malware-family`

A Malware Family is a set of malware instances that are related by common authorship and/or lineage. Malware Families are often named and may have components such as strings that are common across all members of the family.

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The value of this property **MUST** be `malware-family`.
| **id** (required) | [identifier](#identifier) | Specifies a unique ID for the Malware Family.|
| **name** (required) | [name](#name) | Captures the name of the Malware Family, as specified by the producer of the MAEC Package. |
| **aliases** (optional) | [list](#list) of type [name](#name) | Captures aliases for the Malware Family. For cases where the alias comes from an external source, the name of the source **SHOULD** be provided. |
| **labels** (optional) | [list](#list) of type [open-vocab](#open-vocabulary) | Specifies one or more commonly accepted labels to describe the members of the Malware Family, e.g. “worm.” The values for this property **SHOULD** come from the [malware-label-ov](#malware-label) vocabulary.|
| **description** (optional) | [string](#string) | Captures a basic, textual description of the Malware Family. |
| **field_data** (required) | [field-data](#field-data) | Specifies field data about the Malware Family, such as first seen and last seen dates, as well as delivery vectors.|
| **common_strings** (optional) | [list](#list) of type [string](#string) | Specifies any strings common to all members of the Malware Family.|
| **common_capabilities** (optional) | [list](#list) of type [object-ref](#object-reference) | Specifies any Capabilities common to all members of the Malware Family.|
| **common_code_refs** (optional) | [list](#list) of type [capability](#capability) | References code snippets that are shared between all of the members of the Malware Family. The Object(s) referenced **MUST** be of STIX Cyber Observable type artifact and **MUST** be specified in the **observable_objects** property of the Package.|
| **common_behavior_refs** (optional) | [list](#list) of type [identifier](#identifier) | Specifies a set of one or more Behaviors that are common to all of the members of the Malware Family. Each item specifies the unique ID of the Behavior being referenced; accordingly, each referenced item **MUST** be of type `behavior`.|
| **references** (optional) | [list](#list) of type [external-reference](#external-reference) | Captures external references to the Malware Family.|

### Relationships

#### Embedded Relationships
Name | Valid Target(s)
---- | --------------
`common_code_refs` | `artifact`|
`common_behavior_refs` | `behavior`|

#### Common Relationships
`related-to`

#### Top-level Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| `malware-family` | `dropped-by` | `malware-family` | Indicates that the source malware family is dropped by the target malware family.|
| `malware-family` | `derived-from` | `malware-family` | Indicates that the code base of the source malware family is a derived from the code base of the target malware family.|

## Malware Instance

> Basic Malware Instance

```json
{
  "type":"package",
  "id":"package--773adac8-2316-42c6-6fbc-9cdef8876fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "instance_object_refs": ["0"],
        "name": {
           "value":"Zeus 1.3",
           "confidence":50
        },
        "capabilities": [{"name":"anti-detection"}],
        "analysis_metadata": [
           {
              "analysis_type":"in-depth",
              "description": "ran sample through sandbox"
           }
        ]
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes":{"MD5":"4472ea40dc71e5bb701574ea215a81a1"},
        "size":25536,
        "name":"foo.dll"
     }
  }
}
```

> Malware Instance with Malware Actions

```json
{
    "id": "package--3a7b331e-906f-42c0-bfd5-c2cd04076834",
    "type": "package",
    "schema_version": "5.0",
    "maec_objects": [
        {
            "type": "malware-instance",
            "id": "malware-instance--1d43c77c-21a0-4a10-9a9a-8c0fdfd280b8",
            "instance_object_refs": ["0"],
            "dynamic_features": {
                "action_refs": [
                    "malware-action--935a718f-863e-49fb-89b8-d65dc0e70e53",
                    "malware-action--75514819-ea94-4684-8107-68ee63315fc4"
                ]
            }
        },
        {
            "type": "malware-action",
            "id": "malware-action--935a718f-863e-49fb-89b8-d65dc0e70e53",
            "name": "create-file",
            "is_successful": true,
            "output_object_refs": ["0"]
        },
        {
            "type": "malware-action",
            "id": "malware-action--75514819-ea94-4684-8107-68ee63315fc4",
            "name": "write-to-process-memory",
            "is_successful": true,
            "input_object_refs": ["0"],
            "output_object_refs": ["1"]
        }
    ],
    "observable_objects": {
        "0": {
            "type": "file",
            "size": 196608,
            "hashes": {
                "MD5": "4EC0027BEF4D7E1786A04D021FA8A67F"
            },
            "parent_directory_ref": "2"
        },
        "1": {
            "type": "file",
            "name": "msvcr.dll",
            "parent_directory_ref": "parent_directory_ref1"
        },
        "2": {
            "type": "directory",
            "path": "C:\\Documents and Settings\\user\\Local Settings\\Application\\Data"
        },
        "3": {
            "type": "process",
            "name": "explorer.exe",
            "cwd": "C:\\Windows\\"
        }
    }
}
```

**Type Name**: `malware-instance`

A Malware Instance can be thought of as a single member of a Malware Family that is typically packaged as a binary. This type allows for the characterization of the binaries associated with a Malware Instance along with any corresponding analyses, associated Capabilities, Behaviors, and Actions, and relationships to other Malware Instances.

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The value of this property **MUST** be `malware-instance`. |
| **id** (required) | [identifier](#identifier) | Specifies a unique ID for the Malware Instance.|
| **instance_object_refs** (required) | [list](#list) of type [object-ref](#object-reference) | References the Cyber Observable Objects that characterize the packaged code (typically a binary) associated with the Malware Instance Object. For most use cases, the object referenced **SHOULD** be of STIX Cyber Observable type `file`. Objects referenced **MUST** be specified in the **observable_objects** property of the Package. For cases where multiple STIX Observable File Objects are referenced by this property, each Object **MUST** have the same hash value (via the **hashes** property) but **MAY** have different file names (via the **name** property). |
| **name** (optional) | [name](#name) | Captures the name of the Malware Instance, as specified by the producer of the MAEC Package. |
| **aliases** (optional) | [list](#list) of type [name](#name) | Captures any aliases for the name of the Malware Instance, as reported by sources other than the producer of the MAEC document (e.g., AV vendors). |
| **labels** (optional) | [list](#list) of type [open-vocab](#open-vocabulary) | Specifies one or more commonly accepted labels to describe the Malware Instance, e.g. “trojan.” The values for this property **SHOULD** come from the [malware-label-ov](#malware-label) vocabulary.|
| **description** (optional) | [string](#string) | Captures a basic, textual description of the Malware Instance. |
| **field_data** (optional) | [field-data](#field-data) | Specifies field data about the Malware Instance, such as first seen and last seen dates, as well as delivery vectors.|
| **os_execution_envs** (optional) | [list](#list) of type [open-vocab](#open-vocabulary) | Specifies the operating systems that the Malware Instance executes on. The values for this property **SHOULD** come from the [operating-system-ov](#operating-system) vocabulary. |
| **architecture_execution_envs** (optional) | [list](#list) of type [open-vocab](#open-vocabulary) | Specifies the processor architectures that the Malware Instance executes on. The values for this property **SHOULD** come from the [processor-architecture-ov](#processor-architecture) vocabulary. |
| **capabilities** (optional) | [list](#list) of type [capability](#capability) | Specifies a set of one or more Capabilities possessed by the Malware Instance. |
| **os_features** (optional) | [list](#list) of type [open-vocab](#open-vocabulary) | Specifies any operating system-specific features used by the Malware Instance. Each item in the list specifies a single feature. The values for this property **SHOULD** come from the [os-features-ov](#os-features) vocabulary. |
| **dynamic_features** (optional) | [dynamic-features](#dynamic-features) | Captures features associated with the semantics of the code executed by the Malware Instance, such as Malware Actions and Behaviors.|
| **static_features** (optional) | [static-features](#static-features) | Captures features associated with the binary that aren’t related to the semantics of the executed code, such as strings and packer information.|
| **analysis_metadata** (optional) | [list](#list) of type [analysis-metadata](#analysis-metadata) | Captures metadata associated with the analyses performed on the Malware Instance, such as the tools that were used. |
| **triggered_signatures** (optional) | [list](#list) of type [signature-metadata](#signature-metadata) | Captures metadata associated with any signatures or rules (e.g., YARA) that were triggered during the analysis of the malware instance.|

### Relationships

#### Embedded Relationships
Name | Valid Target(s)
---- | --------------
`instance_object_refs` | `file`|

#### Common Relationships
`related-to`

#### Top-level Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| `malware-instance` | `ancestor-of` | `malware-instance` | Indicates that the source malware instance is an ancestor of the target malware instance.|
| `malware-instance` | `downloaded-by` | `malware-family`, `malware-instance` | Indicates that the source malware instance is downloaded by the target malware instance or family.|
| `malware-instance` | `dropped-by` | `malware-family`, `malware-instance` | Indicates that the source malware instance is dropped by the target malware instance or family.|
| `malware-instance` | `derived-from` | `malware-family`, `malware-instance` | Indicates that the code base of the source malware instance is a derived from the code base of the target malware instance or family.|
| `malware-instance` | `extracted-from` | `malware-instance` | Indicates that the source malware instance is extracted from the target malware instance.|
| `malware-instance` | `has-distance` | `malware-instance` | Indicates that the source malware instance has some distance (with respect to similarity) to the target malware instance.|
| `malware-instance` | `has-distance` | `malware-family`, `malware-instance` | Indicates that the source malware instance is installed by the target malware instance or family.|
| `malware-instance` | `variant-of` | `malware-family`, `malware-instance` | Indicates that the source malware instance is a variant of the target malware instance or family.|

# MAEC Types

## API Call

> Malware Action with parameter constants

```json
{
 "type":"package",
 "id":"package--7892dac8-c416-35c6-bc5c-7b6dcf576f91",
 "schema_version":"5.0",
 "maec_objects": [
    {
       "type":"malware-action",
       "id":"malware-action--c095f1ab-0847-4d89-92ef-010e6ed39c20",
       "name":"delete file",
       "output_object_refs": ["3"],
       "api_call": {
          "address":"040089aa",
          "return_value":"0400f258",
          "parameters": {
             "lpFileName":"C:\\Temp\\badfile.pptx",
             "dwDesiredAccess":"GENERIC_WRITE",
             "dwShareMode":"FILE_SHARE_READ",
             "lpSecurityAttributes":"NULL",
             "dwCreationDisposition":"CREATE_NEW",
             "dwFlagsAndAttributes":"FILE_ATTRIBUTE_NORMAL",
             "hTemplateFile":"00000000"
          },
          "function_name":"CreateFileEx"
       }
    }
 ]
}
```

> Malware Action with parameter literals

```json
{
 "type":"package",
 "id":"package--6e8a76ff-9ffa-419e-8ad4-8a165e86f171",
 "schema_version":"5.0",
 "maec_objects": [
    {
       "type":"malware-action",
       "id":"malware-action--2dc56470-bef0-4a32-910f-760a5d62be2b",
       "name":"delete file",
       "input_object_refs": ["1"],
       "api_call": {
          "address":"040089aa",
          "return_value":"1",
          "parameters": {
             "lpFileName":"C:\\Temp\\badfile.pptx",
             "dwDesiredAccess":"40000000",
             "dwShareMode":"0x00000001",
             "lpSecurityAttributes":"0",
             "dwCreationDisposition":"1",
             "dwFlagsAndAttributes":"128",
             "hTemplateFile":"00000000"
          },
          "function_name":"DeleteFile" 
       }
    }
 ]
}

```

**Type Name**: `api-call`

The `api-call` type serves as a method for characterizing API Calls, as implementations of Malware Actions.

Name | Type | Description
--------- | ------- | -----------
| **address** (optional) | [hex](#hex) | Captures the hexadecimal address of the API call in the binary.|
| **return_value** (optional) | [string](#string) | Captures the return value of the API call.|
| **parameters** (optional) | [dictionary](#dictionary) | Captures a list of function parameters. Each key in the dictionary **MUST** be a string that captures the exact name of the parameter, and each corresponding key value **MUST** be a string that captures the corresponding parameter value.  For parameter values that can be represented by a constant, e.g., GENERIC_WRITE, the constant rather than the literal **SHOULD** be used. For cases where the parameter cannot be represented by a constant, the literal (as reported by the tool producing the data) **MUST** be used.|
| **function_name** (required) | [string] (#string) | Captures the full name of the API function called, e.g., `CreateFileEx`.

## Analysis Metadata

> Analysis Metadata

```json
{
 "type":"package",
 "id":"package--7892dac8-c416-35c6-bc5c-7b6dcf576f91",
 "schema_version":"5.0",
 "maec_objects":[
   {
     "type":"malware-instance",
     "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
     "instance_object_refs":[
       "0"
     ],
     "name":{
       "value":"MalwareB.1.1",
       "confidence":80
     },
     "analysis_metadata":[
       {
         "is_automated":false,
         "start_time":"2017-02-05T12:15:00Z",
         "end_time":"2017-02-05T12:20:00Z",
         "last_update_time":"2017-02-05T12:20:00Z",
         "confidence":75,
         "analysts":[
           "John Doe",
           "Jane Doe"
         ],
         "analysis_type":"dynamic",
         "analysis_environment":{
           "operating-system":"2",
           "host-vm":"3",
           "installed-software":[
             "4",
             "5"
           ]
         },
         "comments":[
           "The decryption key is: Infected---key+-34512",
           "Analysis required increase of default timeout value"
         ],
         "tool_refs":[
           "1"
         ],
         "description":"Basic automated sandbox analysis.",
         "conclusion":"malicious"
       }
     ]
   }
 ],
 "observable_objects":{
   "0":{
     "type":"file",
     "hashes":{
       "MD5":"4472ea40dc71e5bb701574ea215a81a1"
     },
     "size":25536
   },
   "1":{
     "type":"software",
     "name":"Cuckoo Sandbox",
     "version":"2.0"
   },
   "2":{
     "type":"software",
     "name":"Windows 7",
     "vendor":"Microsoft"
   },
   "3":{
     "type":"software",
     "name":"Virtualbox",
     "version":"5.0.40",
     "vendor":"Oracle"
   },
   "4":{
     "type":"software",
     "name":"Office 2010",
     "vendor":"Microsoft",
     "version":"14.0.4"
   },
   "5":{
     "type":"software",
     "name":"Java",
     "vendor":"Oracle",
     "version":"1.8.0_40"
   }
 }
}
```

**Type Name**: `analysis-metadata`

The `analysis-metadata` type captures metadata associated with the analyses performed on a malware instance, such as the tools used and the analysts who performed the analysis.

Name | Type | Description
--------- | ------- | -----------
| **is_automated** (required) | [boolean](#boolean) | Captures whether the analysis was fully automated (i.e., no human analyst in the loop). If this property is set to `true`, the **analysts** property **MUST NOT** be included.|
| **start_time** (optional) | [timestamp](#timestamp) |  Captures the date/time that the analysis was started.|
| **end_time** (optional) | [timestamp](#timestamp) |  Captures the date/time that the analysis was completed.|
| **last_update_time** (optional) | [timestamp](#timestamp) |  Captures the date/time that the analysis was last updated.|
| **confidence** (optional) | [integer](#integer) | Captures the relative measure of confidence in the accuracy of the analysis results.  The confidence value **MUST** be a number in the range of 0-100.|
| **analysts** (optional) | [list](#list) of type [string](#string) | Captures the names of analysts who performed the analysis.|
| **analysis_type** (required) | [open-vocab](#open-vocabulary) | Captures the type of analysis performed. The value for this property **SHOULD** come from the [analysis-type-ov](#analysis-type) vocabulary.|
| **comments** (optional) | [list](#list) of type [string](#string) | Captures comments regarding the analysis that was performed. A comment **SHOULD** be attributable to a specific analyst and **SHOULD** reflect particular insights of the author that are significant from an analysis standpoint.|
| **tool_refs** (optional) | [list](#list) of type [object-ref](#object-reference) | References the tools used in the analysis of the Malware Instance. The objects referenced **MUST** be of STIX Cyber Observable type `software` and **MUST** be specified in the **observable_objects** property of the Package.|
| **analysis_environment** (optional) | [dictionary](#dictionary) | Captures any metadata, such as the host virtual machine, associated with the analysis environment used to perform the dynamic analysis of the Malware Instance. Each key in the dictionary **SHOULD** come from the [analysis-environment-ov](#analysis-environment), and each corresponding key value **SHOULD** be a valid `object-ref` or `list` of `object-ref`. This property **MUST NOT** be included if **analysis_type** is set to a value of `static`.|
| **description** (optional) | [string](#string) |  Captures a textual description of the analysis performed.|
| **conclusion** (optional) | [open-vocab](#open-vocabulary) | Captures the conclusion of the analysis, such as whether the binary was found to be malicious. The value for this property **SHOULD** come from the [analysis-conclusion-ov](#analysis-conclusion) vocabulary.|
| **references** (optional) | [list](#list) of type [external-reference](#external-reference) | Captures any references to reports or other data sources pertaining to the analysis.|

## Binary Obfuscation

> Binary Obfuscation

```json
{
  "type":"package",
  "id":"package--2d42dac8-c416-42c6-bc5c-7b6dcf576fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--19863c16-503e-493f-8841-16c68e39c26e",
        "instance_object_refs": ["0"],
        "static_features": {
           "obfuscation_methods": [
              {
                 "method":"packing",
                 "layer_order":1,
                 "packer_name":"UPX"
              },
              {
                 "method":"encryption",
                 "layer_order":2,
                 "encryption_algorithm":"XOR"
              }
           ]
        }
     }
  ]
}
```

**Type Name**: `binary-obfuscation`

The `binary-obfuscation` type captures metadata on the methods that a binary may be obfuscated with, such as executable packers or XOR encryption. This includes obfuscation of the entire binary as well as its constituent pieces, such as strings.

Name | Type | Description
--------- | ------- | -----------
| **method** (required) | [open-vocab](#open-vocabulary) | Captures the method used to obfuscate the binary. The value for this property **SHOULD** come from the [obfuscation-method-ov](#obfuscation-method) vocabulary.|
| **layer_order** (optional) | [integer](#integer) | Captures the ordering of the obfuscation method with respect to other obfuscation methods (if known), as a positive integer. For example, if a binary was packed and then XOR encrypted, the **layer_order** property of the packing layer would equal `1` and the **layer_order** property of the XOR encryption layer would equal `2`.|
| **encryption_algorithm** (optional) | [open-vocab](#open-vocabulary) | Captures the name of the encryption algorithm used by the obfuscation method (if applicable). The values for this property **SHOULD** come from the STIX [encryption-algo-ov](https://docs.google.com/document/d/1ti4Ei_ii_Uc4izHNZlYmBP9NgD5-iVWC--y-3HmGZyg/edit#heading=h.h5b9uravt8oh) vocabulary.|
| **packer_name** (optional) | [string](#string) | Specifies the name of the packer (if applicable).|
| **packer_version** (optional) | [string](#string) | Specifies the version of the packer (if applicable).|
| **packer_entry_point** (optional) | [hex](#hex) | Specifies the entry point address of the packer (if applicable).|
| **packer_signature** (optional) | [string](#string) | Specifies the matching signature detected for the packer (if applicable).|

## Capability

> Capability

```json
{
  "type":"package",
  "id":"package--2d42dac8-c416-42c6-bc5c-7b6dcf576fc5",
  "schema_version":"5.0",
  "maec_objects":[
    {
      "type":"malware-instance",
      "id":"malware-instance--19863c16-503e-493f-8841-16c68e39c26e",
      "instance_object_refs":[
        "0"
      ],
      "labels":[
        "mass-mailer",
        "worm"
      ],
      "capabilities":[
        {
          "name":"persistence",
          "refined_capabilities":[
            {
              "name":"continuous-execution"
            },
            {
              "name":"system-re-infection"
            }
          ],
          "description":"The instance persists after a system reboot.",
          "attributes":{
            "persistence-scope":[
              "self",
              "other malware/components"
            ],
            "technique":"creates registry key"
          },
          "behavior_refs":[
           "behavior--1",
            "behavior--2"
          ],
          "references":[
            {
              "source_name":"ATT&CK",
              "description":"Persistence",
              "url":"https://attack.mitre.org/wiki/Persistence"
            }
          ]
        }
      ]
    }
  ]
}
```

**Type Name**: `capability`

The `capability` type captures details of a Capability implemented by a malware instance. A Capability corresponds to a high-level ability that a malware instance possesses, such as persistence or anti-behavioral analysis. Malware Instances and Families may share Capabilities; however, the associated Behaviors implementing the Capabilities will often differ. Therefore, Capabilities are defined inline to Malware Instances and Malware Families rather than as top level objects that are subsequently referenced.

Name | Type | Description
--------- | ------- | -----------
| **name** (required) | [open-vocab](#open-vocabulary) | Captures the name of the Capability. The values for this property **SHOULD** come from the [capability-ov](#capabilities) vocabulary. When used as part of a refined Capability, the values for this property **SHOULD** come from the [refined-capability-ov](#refined-capability) vocabulary.|
| **refined_capabilities** (optional) | [list](#list) of type [capability](#capability) | Captures a refinement of the Capability, recursively using `capability` type.|
| **description** (optional) | [string](#string) | Captures a textual description of the Capability.|
| **attributes** (optional) | [dictionary](#dictionary) | Captures attributes of the Capability as key/value pairs. Each key in the dictionary **MUST** be a string that captures the name of the attribute and **SHOULD** come from the [common-attribute-ov](#common-attribute) vocabulary. Each corresponding key value **MUST** be a string or list of strings that captures the corresponding attribute values.|
| **behavior_refs** (optional) | [list](#list) of type [identifier](#identifier) | Captures the IDs of Behaviors that implement the Capability. Each referenced entity **MUST** be of type `behavior` and each Behavior **MUST** be present in the current Package.|
| **references** (optional) | [list](#list) of type [external-reference](#external-reference) | Captures external references to ATT&CK Tactics and other entities that may be associated with the Capability.|

## Dynamic Features

> Dynamic Features

```json
{
  "type":"package",
  "id": "package--2d42dac8-c416-42c6-bc5c-7b6dcf576fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--19863c16-503e-493f-8841-16c68e39c26e",
        "instance_object_refs": ["0"],
        "dynamic_features": {
           "behavior_refs": ["behavior--1", "behavior--2"],
           "action_refs": ["malware-action--1", "malware-action--2"],
           "network_traffic_refs": ["4"],
           "process_tree": [
             {          
                 "process_ref":"1",
                 "ordinal_position":0 
              }
           ]
        }
     },
     {
        "type":"behavior",
        "id":"behavior--1",
        "name":"persist after system reboot",
        "description":"System reboot persistence via registry startup",
        "action_refs": ["malware-action--1"]
     }
  ],
  "observable_objects": {
     "0": {
        "type": "file",
        "hashes": {"MD5": "66e2ea40dc71d5ba701574ea215a81f1"}
     },
     "1": {
        "type": "process",
        "pid": "1234"
     },
     "2": {
        "type": "process",
        "pid": "2345"
    },
     "3": {
        "type": "domain-name",
        "value": "example.com"
     },
     "4": {
        "type": "network-traffic",
        "dst_ref": "0",
        "protocols": [
           "ipv4",
           "tcp",
           "http"
        ]
     }
  }
}
```

**Type Name**: `dynamic-features`

The `dynamic-features` type captures the dynamic features (i.e., those associated with the semantics of the executed code, of a malware instance).

*Requirement*: At least one of **behavior_refs** or **action_refs** or **network_traffic_refs** or **process_tree** **MUST** be included when using this type.

Name | Type | Description
--------- | ------- | -----------
| **behavior_refs** (optional) | [list](#list) of type [identifier](#identifier) | Captures the IDs of Behaviors exhibited by the Malware Instance. Each referenced entity **MUST** be of type `behavior`.|
| **action_refs** (optional) | [list](#list) of type [identifier](#identifier) | Captures the IDs of Actions discovered for the Malware Instance. Each referenced entity **MUST** be of type `malware-action`. This property is intended for capturing Actions that are discovered through static analysis, reverse engineering, or other methods and therefore **MUST NOT** be used to reference any of the Actions that are included in the **process_tree** property. As such, the Actions referenced by this property are mutually exclusive with respect to the Actions referenced by the **process_tree** property.|
| **network_traffic_refs** (optional) | [list](#list) of type [object-ref](#object-reference) | Captures any network traffic recorded for the Malware Instance. The Object(s) referenced **MUST** be of STIX Cyber Observable type `network-traffic` OR `artifact` (for including binaries of captured traffic such as PCAPs) and **MUST** be specified in the observable_objects property of the Package.|
| **process_tree** (optional) | [list](#list) of type [process-tree-node](#process-tree-node) | Captures the Process Tree observed during the execution of the Malware Instance. This property may also capture Actions that are executed by a process and captured by dynamic analysis/sandboxing and therefore **MUST NOT** be used to reference any of the Actions that are included in the **action_refs** property. As such, the Actions referenced by this property are mutually exclusive with respect to the Actions referenced by the **action_refs** property.|

## Field Data

> Field Data

```json
{
  "type":"package",
  "id":"package--6864e55f-5f5f-451a-843e-8c66913ae116",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-family",
        "id":"malware-family--8ff5814d-0c2e-5601-b8a5-d0032bb03847",
        "name": {
           "value": "Cryptolocker",
           "confidence": 85
        },
        "field_data": {
           "delivery_vectors":["trojanized-link", "downloader"],
           "first_seen":"2013-09-05T00:00:00Z",
           "last_seen":"2017-01-05T00:00:00Z"
        }
     }
  ]
}
```

**Type Name**: `field-data`

The `field-data` type captures field data, such as the time that the malware instance or family was first observed, associated with a malware instance or family.

*Requirement*: At least one of **delivery_vectors** or **first_seen** or **last_seen** **MUST** be included when using this type.

Name | Type | Description
--------- | ------- | -----------
| **delivery_vectors** (optional) | [list](#list) of type [open-vocab](#open-vocabulary) | Captures the vectors used to distribute/deploy the Malware Instance. The values for this property **SHOULD** come from the [delivery-vector-ov](#delivery-vector) vocabulary.|
| **first_seen** (optional) | [timestamp](#timestamp) | Captures the date/time that the malware instance was first seen by the producer of the Malware Instance Object.|
| **last_seen** (optional) | [timestamp](#timestamp) | Captures the date/time that the malware instance was last seen by producer of the Malware Instance Object.|

## Malware Development Environment

> Malware Development Environment

```json
{
  "type":"package",
  "id":"package--2f5d32d0-2f41-48a1-b272-fa5f0390dbd3",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--90153d4d-092e-1601-b8a5-11312bb0388d",
        "instance_object_refs":["0"],
        "name": {
           "value": "RansomW.cb",
           "confidence": 20
        },
        "static_features": [
           {
              "development_environment": [
                 {
                    "tool_refs": ["4"]
                 }
              ]
           }
        ]
     }
  ],
  "observable_objects": {
     "0": {
        "type": "file",
        "hashes": {"MD5": "66e2ea40dc71d5ba701574ea215a81f1"}
     },
     "4": {
        "type":"software",
        "name":"gcc"
     }
  }
}
```

**Type Name**: `malware-development-environment`

The `malware-development-environment` captures details of the development environment used in developing the malware instance, such as information on any tools that were used. 

*Requirement*: At least one of **tool_refs** or **debugging_file_refs** **MUST** be included when using this type.

Name | Type | Description
--------- | ------- | -----------
| **tool_refs** (optional) | [list](#list) of type [object-ref](#object-reference) | References the tools used in the development of the malware instance. The Objects referenced **MUST** be of STIX Cyber Observable type `software` and **MUST** be specified in the **observable_objects** property of the Package.|
| **debugging_file_refs** (optional) | [list](#list) of type [object-ref](#object-reference) | References debugging files associated with the malware instance, such as PDB files. The Objects referenced **MUST** be of STIX Cyber Observable type `file` and **MUST** be specified in the **observable_objects** property of the Package.|

## Name

> Name

```json
{
  "type":"package",
  "id":"package--d7b38d7d-f587-4556-a786-0cd2ee10bf5d",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--90153d4d-092e-1601-b8a5-11312bb0388d",
        "name": {
           "value": "Conficker.A",
           "source": {
              "source_name": "Conficker Threat Intel",
              "description": "Analysis details of Conficker by Amanda Analyst",
              "url": "http://www.example.com/threat-report.pdf"
           },
           "confidence": 80
        }
     }
  ]
}
```

**Type Name**: `name`

The `name` type captures the name of a malware instance, family, or alias, as well as the source and relative confidence in the name.

Name | Type | Description
--------- | ------- | -----------
| **value** (required) | [string](#string) | Captures the name of the malware instance, family, or alias.|
| **source** (optional) | [external-reference](#external-reference) | Captures the internal or external source of the value property (i.e., the name).|
| **confidence** (optional) | [integer](#integer) | Captures the relative confidence in the accuracy of the assigned name. The confidence value **MUST** be a number in the range of 0-100.|

## Process Tree Node

> Process Tree Node

```json
{
  "type":"package",
  "id": "package--2d42dac8-c416-42c6-bc5c-7b6dcf576fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--19863c16-503e-493f-8841-16c68e39c26e",
        "instance_object_refs": ["0"],
        "dynamic_features": {
           "behavior_refs": ["behavior--1", "behavior--2"],
           "process_tree": [
              {
                 "process_ref":"1",
                 "ordinal_position":0
               }
           ]
        }
     }
  ],
  "observable_objects": {
     "0": {
        "type": "file",
        "hashes": {"MD5": "66e2ea40dc71d5ba701574ea215a81f1"}
     },
     "1": {
        "type": "process",
        "pid": 1234
     },
     "2": {
        "type": "process",
        "pid": 2345
     },
     "3": {
        "type": "process",
        "pid": 5678
     }
  }
}
```

**Type Name**: `process-tree-node`

The `process-tree-node` type captures a single node in a process tree, as recorded for a Malware Instance.

Name | Type | Description
--------- | ------- | -----------
| **process_ref** (required) | [object-ref](#object-reference) | References the Process Object, contained in the Package, which represents the process and its relevant metadata. The Object referenced **MUST** be of STIX Cyber Observable type `process` and **MUST** be specified in the **observable_objects** property of the Package.|
| **parent_action_ref** (optional) | [identifier](#identifier) | Captures the ID of the Action that created or injected the process. The referenced entity **MUST** be of type `malware-action`.|
| **ordinal_position** (optional) | [integer](#integer) | Captures the ordinal position of the process with respect to the other processes spawned or injected by the malware. This value **MUST** be a non-negative integer. For specifying the root process of the process tree, a value of `0` **MUST** be used.|
| initiated_action_refs** (optional) | [list](#list) of type [identifier](#identifier) | Captures the IDs of the Actions initiated by the process. Each referenced entity **MUST** be of type `malware-action`.

## Relationship Distance

> Relationship Distance

```json
{
  "type":"package",
  "id":"package--0987dac8-2316-52c6-6fbc-074ef8876fdd",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "instance_object_refs": ["0"]
     },
     {
        "type":"malware-instance",
        "id":"malware-instance--bacd8340-83bd-94ad-0111-f029304ced90",
        "instance_object_refs": ["1"]
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes": {"MD5":"4472ea40dc71e5bb701574ea215a81a1"}
     },
     "1": {
        "type":"file",
        "hashes": {"MD5":"39C8E9953FE8EA40FF1C59876E0E2F28"}
     }
  },
  "relationships": [
     {
        "type":"relationship",
		"id":"relationship--ffc99c9c-8765-4a36-b416-65dde178b008",
        "source_ref":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "target_ref":"malware-instance--bacd8340-83bd-94ad-0111-f029304ced90",
        "relationship_type":"has-distance",
        "metadata": {
           "distance": {
             "distance_score":0.92,
             "algorithm_name":"clusterAlgorithm-abc",
             "algorithm_version":"6.1",
             "metadata":{"foo":"bar"}
           }
        }
     }
  ]
}
```

**Type Name**: `relationship-distance`

The `relationship-distance` type captures a distance score and associated metadata between the source and target in a MAEC relationship.

Name | Type | Description
--------- | ------- | -----------
| **distance_score** (required) | [float](#float) | Captures the distance score between the source and target in the relationship. This is most commonly represented as a floating point value between zero and one (with a higher value representing a greater distance).|
| **algorithm_name** (optional) | [string](#string) | Captures the name of the algorithm or tool used in calculating the distance score specified in the `distance_score` property.|
| **algorithm_version** (optional) | [string](#string) | Captures the version of the algorithm or tool used in calculating the distance score specified in the `distance_score` property.|
| **metadata** (optional) | [dictionary](#dictionary) | Specifies a dictionary of additional metadata around the distance score, as a set of key/value pairs. Dictionary keys and their corresponding values **MUST** be of type `string`.|

## Signature Metadata

> Signature Metadata

```json
{
  "type":"package",
  "id":"package--2d42dac8-c416-42c6-bc5c-7b6dcf576fc5",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--19863c16-503e-493f-8841-16c68e39c26e",
        "instance_object_refs": ["0"],
        "triggered_signatures": [
           {
              "signature_type":"yara",
              "description":"Ransomware",
              "author":"John Doe",
              "reference":{
                 "url": "http://foo.bar"
              },
              "severity":"9.0"
           },
           {
              "signature_type":"cuckoo",
              "description":"Anti-sandbox sleep",
              "author":"Jane Doe",
              "reference":{
                 "url":"http://bar.foo"
              },
              "severity":"5.0"
           }
        ]
     }
  ]
}
```

**Type Name**: `signature-metadata`

The `signature-metadata` type captures metadata associated with a signature (for example, a YARA rule) that may have been triggered during the analysis of a malware instance.

*Requirement*: In addition to **signature_type**, at least one of the **name** or **description** properties **MUST** be included when using this type.

Name | Type | Description
--------- | ------- | -----------
| **signature_type** (optional) | [string](#string) | Captures the type of the signature, i.e., the language or platform it is written for. For example, “snort”, for the Snort network intrusion detection system (NIDS). The name of the language or platform **SHOULD** be in lowercase, with any whitespace replaced with dashes (i.e., “-”).|
| **name** (optional) | [string](#string) | Captures the name provided for the signature (if applicable).|
| **description** (optional) | [string](#string) | Captures a textual description of the signature.|
| **author** (optional) | [string](#string) | Captures the name of the author of the signature.|
| **reference** (optional) | [external-reference](#external-reference) | Captures an external reference associated with the signature.|
| **severity** (optional) | [string](#string) | Captures a measure of severity associated with the detection of the signature.|
| **external_id** (optional) | [string](#string) | Captures an external identifier associated with the signature.|

## Static Features

> Static Features

```json
{
  "type":"package",
  "id":"package--b7be50bd-6348-4226-bef9-4c3510f698f7",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--90153d4d-092e-1601-b8a5-11312bb0388d",
        "name": {
           "value": "Malcode.13",
           "confidence": 50
        },
        "static_features": {
           "strings": ["This string is key.", "This is another string in the instance"],
           "obfuscation_methods": [
              {
                 "method":"packing",
                 "ordering":1,
                 "packer_name":"UPX"     
              },
              {
                 "method":"encryption",
                 "ordering":1,
                 "encryption_algorithm":"XOR"     
              }
           ],
           "configuration_parameters": [
              {
                 "name":"magic-number",
                 "value":"0x674dfe60abee3234"
              },
              {
                 "name":"directory",
                 "value":"C:\\Users\\<username>\\Desktop"
              }
           ],
           "development_environment": {
              "tool_refs": ["4"],
              "debugging_file_refs": ["6"]
           }
        } 
     }
  ]
}
```

**Type Name**: `static-features`

The `static-features` type captures features associated with a malware instance (a binary file) not related to the semantics of the code.

*Requirement*: At least one of **strings** or **obfuscation_methods** or **certificates** or **file_headers** or **configuration_parameters** or **development_environment properties** **MUST** be included when using this type.

Name | Type | Description
--------- | ------- | -----------
| **strings** (optional) | [list](#list) of type [string](#string) | Captures any strings that were extracted from the malware instance.|
| **obfuscation_methods** (optional) | [list](#list) of type [binary-obfuscation](#binary-obfuscation) | Captures metadata associated with methods used to obfuscate the malware instance (e.g., packers, encryptors).|
| **certificates** (optional) | [list](#list) of type [object-ref](#object-reference) | References any software certificates used to sign the malware instance. The Objects referenced **MUST** be of STIX Cyber Observable type `x509-certificate` and **MUST** be specified in the **observable_objects** property of the Package.|
| **file_headers** (optional) | [list](#list) of type [object-ref](#object-reference) | References any file headers (e.g., PE file headers) extracted from the malware instance. The Objects referenced **MUST** be of STIX Cyber Observable type `file` and **MUST** be specified in the **observable_objects** property of the Package.|
| **configuration_parameters** (optional) | [dictionary](#dictionary) | Captures any configuration parameters specified for the malware instance. Each key in the dictionary **MUST** be of type `string` and **SHOULD** come from the [malware-configuration-parameter-ov](#malware-configuration-parameter) vocabulary, which is based on the data reported by the Malware Configuration Parser (MWCP) tool developed by the Department of Defense Cyber Crime Center (DC3). Each corresponding key value **MUST** also be of type `string`, and should capture the actual value of the configuration parameter.|
| **development_environment** (optional) | [malware-development-environment](#malware-development-environment) | Captures details of the development environment used to create the malware instance.|

# Relationships

> Relationship between Malware Instances ("downloaded-by")

```json
{
  "type":"package",
  "id":"package--0987dac8-2316-52c6-6fbc-074ef8876fdd",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "instance_object_refs": ["0"]
     },
     {
        "type":"malware-instance",
        "id":"malware-instance--bacd8340-83bd-94ad-0111-f029304ced90",
        "instance_object_refs": ["1"]
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes": {"MD5":"4472ea40dc71e5bb701574ea215a81a1"}
     },
     "1": {
        "type":"file",
        "hashes": {"MD5":"39C8E9953FE8EA40FF1C59876E0E2F28"}
     }
  },
  "relationships": [
     {
        "type":"relationship",
        "id":"relationship--dcc7d8d4-91c0-412a-8d09-a030ab19e0f1",
        "source_ref":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "target_ref":"malware-instance--bacd8340-83bd-94ad-0111-f029304ced90",
        "relationship_type":"downloaded-by"
     }
  ]
}
```

> Relationship between Malware Instances ("has-distance")

```json
{
  "type":"package",
  "id":"package--dbd7a6ae-9dfc-48a2-9e6e-bf85f0c8613b",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--c90945ec-ea66-4c61-9bd4-72e66aeb464e",
        "instance_object_refs": ["0"]
     },
     {
        "type":"malware-instance",
        "id":"malware-instance--ce40a5c7-f3af-4b64-90e2-2884194192ab",
        "instance_object_refs": ["1"]
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes": {"MD5":"aafdea40dc71e5bb701574ea215a81a1"}
     },
     "1": {
        "type":"file",
        "hashes": {"MD5":"3ABCE9953FE8EA40FF1C59876E0E2F28"}
     }
  },
  "relationships": [
     {
        "type":"relationship",
        "id":"relationship--0bc99c9c-8765-4a36-b416-bbdde178b5a4",
        "source_ref":"malware-instance--c90945ec-ea66-4c61-9bd4-72e66aeb464e",
        "target_ref":"malware-instance--ce40a5c7-f3af-4b64-90e2-2884194192ab",
        "relationship_type":"has-distance",
        "metadata":{"distance":{"distance_score":"0.35",
                                "algorithm_name":"FooDist"}}
     }
  ]
}
```

**Type Name**: `relationship`

The Relationship Object captures relationships between two entities in a MAEC Package. If MAEC TLOs are considered "nodes" or "vertices" in the graph, the Relationship Object represent "edges". Explicit relationships between MAEC Top Level Objects are provided above in the MAEC specification. Note that MAEC relationships cannot be the source or target of another relationship.

MAEC defines many relationship types to link together some TLOs. These relationships are contained in the "Relationships" table under each TLO definition. Relationship types defined in the specification **SHOULD** be used to ensure consistency. An example of a specification-defined relationship is that a `malware-instance` is `downloaded-by` a `malware-instance`. That relationship type is listed in the Relationships section of the Malware Instance TLO definition.

MAEC also allows relationships from any TLO to any TLO that have not been defined in the specification. These relationships **MAY** use the generic `related-to` relationship type or **MAY** use a custom relationship type. As an example, a user might want to link `malware-instance` directly to a `collection`. They can do so using `related-to` to say that the Malware is related to the Collection but not describe how, or they could use `has-common-artifacts` (a custom name they determined) to indicate more detail.

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The value of this property **MUST** be `relationship`.|
| **id** (required) | [identifier](#identifier) | Specifies a unique ID for the Relationship.|
| **source_ref** (required) | [identifier](#identifier) | Specifies a reference to the ID of the entity in the MAEC document that corresponds to the source in the source-target relationship. The referenced entity **MUST** be present in the current Package.|
| **target_ref** (required) | [identifier](#identifier) | Specifies a reference to the ID of the entity in the MAEC document that corresponds to the target in the source-target relationship. The referenced entity **MUST** be present in the current Package.|
| **timestamp** (optional) | [timestamp](#timestamp) | Specifies a timestamp that states when the relationship was created.|
| **relationship_type** (required) | [string](#string) | Specifies the type of relationship being expressed. This value **SHOULD** be an exact value listed in the relationships for the source and target top-level object, but **MAY** be any string. The value of this field **MUST** be in ASCII and is limited to characters a–z (lowercase ASCII), 0–9, and dash (-).|
| **metadata** (optional) | [dictionary](#dictionary) | Specifies a dictionary of additional metadata around the relationship. Standard dictionary keys include `distance`, which is used for capturing any distance-related metadata. The corresponding value for this key **MUST** be an object of type `relationship-distance`. Custom entries in the dictionary **MAY** also be included. Each custom entry **MUST** have a key of type `string` and the key **MUST** be in ASCII and is limited to characters a–z (lowercase ASCII), 0–9, and dash (-). Each custom entry **MUST** have a key value that is a valid [common datatype](#Common-Data-Types).

## Common Relationships

Each MAEC top-level object has its own set of relationship types that are specified in the definition of that TLO. The following common relationship types are defined for all TLOs.

Relationship Type | Source | Target | Description
--------- | ------- | ----------- | --------------
| `related-to` | `<MAEC Object>` | `<MAEC Object>` | Asserts a non-specific relationship between two TLOs. This relationship can be used when none of the other predefined relationships are appropriate.|

## Relationship Summary

This relationship summary is provided as a convenience. If there is a discrepancy between this table and the relationships defined with each of the TLOs, then the relationships defined with the TLOs **MUST** be viewed as authoritative.

Source | Relationship Type | Target 
--------- | ------- | ----------- 
| `behavior` | `dependent-on` | `behavior` |
| `behavior` | `discovered-by` | `software` |
| `malware-action` | `dependent-on` | `malware-action` |
| `malware-action` | `discovered-by` | `software` |
| `malware-family` | `dropped-by` | `malware-family` |
| `malware-family` | `derived-from` | `malware-family` |
| `malware-instance` | `ancestor-of` | `malware-instance` |
| `malware-instance` | `has-distance` | `malware-instance` |
| `malware-instance` | `installed-by` | `malware-family` |
| `malware-instance` | `installed-by` | `malware-instance` |
| `malware-instance` | `derived-from` | `malware-family` |
| `malware-instance` | `derived-from` | `malware-instance` |
| `malware-instance` | `variant-of` | `malware-family` |
| `malware-instance` | `variant-of` | `malware-instance` |
| `malware-instance` | `downloaded-by` | `malware-family` |
| `malware-instance` | `downloaded-by` | `malware-instance` |
| `malware-instance` | `dropped-by` | `malware-family` |
| `malware-instance` | `dropped-by` | `malware-instance` |
| `malware-instance` | `extracted-from` | `malware-instance` |

# Package

> Package

```json
{
  "type":"package",
  "id":"package--0987dac8-2316-52c6-6fbc-074ef8876fdd",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "instance_object_refs": ["0"]
     },
     {
        "type":"malware-instance",
        "id":"malware-instance--bacd8340-83bd-94ad-0111-f029304ced90",
        "instance_object_refs": ["1"]
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes": {"MD5":"4472ea40dc71e5bb701574ea215a81a1"}
     },
     "1": {
        "type":"file",
        "hashes": {"MD5":"39C8E9953FE8EA40FF1C59876E0E2F28"}
     }
  },
  "relationships": [
     {
        "type":"relationship",
        "source_ref":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "target_ref":"malware-instance--bacd8340-83bd-94ad-0111-f029304ced90",
        "relationship_type":"downloaded-by"
     }
  ]
}
```
**Type Name**: `package`

The `package` is the standard output format that can be used to capture one or more Malware Instances or Malware Families and the entities associated with them: Capabilities, Behaviors, Actions, Cyber Observable Objects, and Collections and Relationships.

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The value of this property **MUST** be `package`.|
| **id** (required) | [identifier](#identifier) | Specifies the ID for the Package.|
| **schema_version** (required) | [string](#string) | Specifies the version of the MAEC specification used to represent the content in this Package. The value of this property **MUST** be `5.0`.
| **maec_objects** (required) | [list](#list) of type [\<MAEC Object\>](#Top-level-Objects) | Specifies MAEC Objects. Objects in this list **MUST** be valid MAEC Top-level Objects.|
| **observable_objects** (optional) | [stix-observable-objects](#Observable-Objects) | Specifies a dictionary of STIX Cyber Observable Objects relevant to the MAEC Package. This dictionary **MUST** contain all Cyber Observable Objects associated with the MAEC Package, including those that are referenced by other Cyber Observable Objects.|
| **relationships** (optional) | [list](#list) of type [relationship](#relationship) | Specifies a set of one or more MAEC Relationships. Each entry in this list **MUST** be of type relationship.|


# STIX Cyber Observable Object Extensions

## AV Classification
The following are MAEC-specific extensions defined for STIX Cyber Observable Objects used in the context of MAEC.

> AV Classification

```json
{
  "type":"package",
  "id":"package--e2ea70f1-02af-4560-8712-34e1d138393e",
  "schema_version":"5.0",
  "observable_objects": {
     "0": {
        "type":"file",
        "name":"a92e5b2bae.exe",
        "hashes": {"MD5":"a92e5b2bae0b4b3a3d81c85610b95cd4"},
        "extensions": {
           "x-maec-avclass": [
              {
                 "scan_date":"2010-05-15T03:38:44Z",
                 "is_detected":false,
                 "av_name":"Security Essentials",
                 "av_vendor":"Microsoft",
                 "av_engine_version":"4.2.3",
                 "av_definition_version":"032415-0011"
              },
              {
                 "scan_date":"2010-05-18T12:43:12Z",
                "is_detected":true,
                 "classification_name":"Trojan.Zeus",
                 "av_vendor":"McAfee"
              }
           ]
        }
     }
  }
}
```

**Type Name**: `x-maec-avclass`

The `x-maec-avclass` extension captures information on anti-virus (AV) tool classifications for a particular file. Note that unlike other extensions, the base type of this extension is `list`, with each entry in the list (of type `dictionary`) representing a single AV classification. This custom extension **MUST** only be used in conjunction with the STIX Cyber Observable [File Object](https://docs.google.com/document/d/167aIyr5BIAJJORzjT11U25cGSBJ0cBNSdkheNJFz6l8/edit#heading=h.99bl2dibcztv).

Name | Type | Description
--------- | ------- | -----------
| **scan_date** (required) | [timestamp](#timestamp) | Captures the date and time of the scan. This property can be used to track how scans change over time.|
| **submission_date** (optional) | [timestamp](#timestamp) | Captures the date and time that the binary was submitted for scanning.|
| **is_detected** (optional) | [boolean](#boolean) | Captures whether the AV tool specified in the `x-maec-avclass` extension has detected the malware instance.|
| **classification_name** (optional) | [string](#string) | Captures the classification assigned to the malware instance by the AV tool.|
| **av_name** (optional) | [string](#string) | Captures the name of the AV tool that generated the classification.|
| **av_vendor** (optional) | [string](#string) | Captures the name of the vendor of the AV tool that generated the classification.|
| **av_version** (optional) | [string](#string) | Captures the version of the AV tool that generated the classification.|
| **av_engine_version** (optional) | [string](#string) | Captures the version of the AV engine used by the AV tool that generated the classification.|
| **av_definition_version** (optional) | [string](#string) | Captures the version of the AV definitions used by the AV tool that generated the classification.|

# Common Data Types

## Boolean

> Boolean

```json
{
  ...
  "is_encoded": true,
  ...
}
```

**Type Name**: `boolean`

A `boolean` data type has two possible values: `true` or `false`.

The JSON MTI serialization uses the JSON boolean type, which is a literal (unquoted) `true` or `false`.

## Dictionary

> Dictionary

```json
{
  ...
  "attributes": {
     "file type":"pdf",
     "encryption algorithm":"rc4"
  }
  ...
}
```

**Type Name**: `dictionary`

The `dictionary` data type captures an arbitrary set of key/value pairs.

*Requirements*:

Dictionary keys:

* **MUST** be unique in each dictionary.
* **MUST** be in ASCII.
* **MUST** be limited to the characters a-z (lowercase ASCII), A-Z (uppercase ASCII), numerals 0-9, hyphen (-), and underscore (_). 
* **SHOULD** be no longer than 30 ASCII characters in length.
* **MUST** have a minimum length of 3 ASCII characters.
* **MUST** be no longer than 256 ASCII characters in length.
* **SHOULD** be lowercase. 

Dictionary values:

* **MUST** be valid common data types.

## External Reference

> External-reference #1

```json
{
  ...
  "references": [
     {
        "source_name": "ACME Threat Intel",
        "description": "Threat report",
        "url": "http://www.example.com/threat-report.pdf"
     }
  ]
  ...
}
```

> External-reference #2

```json
{
  ...
  "references": [
     {"url":"https://collaborate.mitre.org/maec/index.php/Behavior:45"},
     {"url":"https://collaborate.mitre.org/maec/index.php/Behavior:45/13"}
  ]
  ...
}
```

**Type Name**: `external-reference`

The `external-reference` data type describes pointers to information represented outside of MAEC. For example, a Malware Instance object could use an external reference to indicate an ID for that malware in an external database or a report could use references to represent source material.

The JSON MTI serialization uses the JSON object type when representing external-reference.

*Requirements*: In addition to the **source_name** property, at least one of the **description**, **url**, or **external_id** properties **MUST** be present.

Name | Type | Description
--------- | ------- | -----------
| **source_name** (required) | [string](#string) | The source within which the `external-reference` is defined (system, registry, organization, etc.).|
| **description** (optional) | [string](#string) | A human readable description.|
| **url** (optional) | [string](#string) | A URL reference to an external resource.|
| **external_id** (optional) | [string](#string) | An identifier for the external reference content.|

## Float

> Float

```json
{
  ...
  "distance": 8.321,
  ...
}
```

**Type Name**: `float`

The `float` data type represents an IEEE 754 double-precision number (e.g., a number with a fractional part). However, because the values ±Infinity and NaN are not representable in JSON, they are not valid values in MAEC.

In the JSON MTI serialization, floating point values are represented by the JSON number type.

## Hexadecimal

> Hexadecimal

```json
{
  ...
  "file_offset":"0400af88"
  ...
}
```

**Type Name**: `hex`

The `hex` data type encodes an array of octets (8-bit bytes) as hexadecimal. The string **MUST** consist of an even number of hexadecimal characters, which are the digits '0' through '9' and the letters 'a' through 'f'.

## Identifier

> Identifier

```json
{
  ...
  "behaviors": [
     {
        "type": "behavior",
        "id": "behavior--c2f01ec8-42ff-403e-9e76-b4e8a1ffe1b8",
        "name": "persist after system reboot"
     }
  ]
  ...
}
```

**Type Name**: `identifier`

The `identifier` data type universally and uniquely identifies a MAEC Top Level Object, Relationship Object, or Package. Identifiers (IDs) **MUST** follow the form `object-type--UUIDv4`, where `object-type` is the exact value (all type names are lowercase strings, by definition) from the **type** property of the object being identified or referenced and where the `UUIDv4` is an RFC 4122-compliant Version 4 UUID. The UUID **MUST** be generated according to the algorithm(s) defined in RFC 4122, Section 4.4 (Version 4 UUID).

The JSON MTI serialization uses the JSON string type when representing `identifier`.

## Integer

> Integer

```json
{
  ...
  "count": 8,
  ...
}
```

**Type Name**: `integer`

The integer data type represents a number without any fractional or decimal part. Unless otherwise specified, all integers **MUST** be capable of being represented as a signed 64-bit value ([-(2**63)+1, (2**63)-1]). Additional restrictions **MAY** be placed on the type as described where it is used.

In the JSON MTI serialization, integers are represented by the JSON number type.

## List

> List

```json
{
  ...
  "action_refs": [
     "malware-action--c095f1ab-0847-4d89-92ef-010e6ed39c20",
     "malware-action--80f3f63a-d5c9-4599-b9e4-2a2bd7210736",
     "malware-action--5643f634-fff9-4b39-34a4-76fed73d0dd6"
  ],
  ...
}
```

**Type Name**: `list`

The `list` data type defines an ordered sequence of values. The phrasing “`list` of type `<type>`” is used to indicate that all values within the list **MUST** conform to the specific type. For instance, `list` of type `integer` means that all values of the list must be of the `integer` type. This specification does not specify the maximum number of allowed values in a list, however every instance of a list **MUST** have at least one value. Specific MAEC object properties may define more restrictive upper and/or lower bounds for the length of the list.

Empty lists are prohibited in MAEC and **MUST NOT** be used as a substitute for omitting the property if it is optional. If the property is required, the list **MUST** be present and **MUST** have at least one value.

The JSON MTI serialization uses the JSON array type, which is an ordered list of zero or more values.

## Object Reference

>Object Reference -  illustrates the referencing of a malware binary (represented as a STIX Cyber Observable File Object) by a Malware Instance.

```json
{
  "type":"package",
  "id":"package--7892dac8-c416-35c6-bc5c-7b6dcf576f91",
  "schema_version":"5.0",
  "maec_objects": [
     {
        "type":"malware-instance",
        "id":"malware-instance--b965814d-0c2e-4e01-b8a5-d8c32bb038e6",
        "instance_object_refs": ["0"]
     }
  ],
  "observable_objects": {
     "0": {
        "type":"file",
        "hashes":{"MD5":"4472ea40dc71e5bb701574ea215a81a1"},
        "size":25536
     }
  }
}
```

**Type Name**: `object-ref`

The `object-ref` data type specifies a reference to a STIX Observable Object captured in the MAEC Package **observable_objects** property  (`stix-observable-objects`). The reference **MUST** be valid within the scope of the local Package and **MUST** reference a STIX Cyber Observable of one of the following types:

* artifact
* autonomous-system
* directory
* domain-name
* email-addr
* email-message
* file
* ipv4-addr
* ipv6-addr
* mac-addr
* network-traffic
* process
* software
* url
* user-account
* windows-registry-key
* x509-certificate

## Observable Objects

> Observable Object - illustrates the capture of a STIX Network Traffic Object and an associated IPv4 Address Object.
 
```json
{
 "0": {
   "type": "ipv4-addr",
   "value": "198.51.100.2"
 },
 "1": {
   "type": "network-traffic",
   "dst_ref": "0"
 }
}
```

**Type Name**: `stix-observable-objects`

The `stix-observable-objects` data type is a dictionary (see the `dictionary` data type) where the keys are used as references to the values, which are STIX Observable Objects. Each key in the dictionary **SHOULD** be a non-negative monotonically increasing integer, starting at the value 0 and incrementing by 1, and represented as a string within the JSON MTI serialization. However, implementers **MAY** elect to use an alternate key format.

## Open Vocabulary

> Example using a value from an open vocabulary
```json
{
  ...
  "structural_features": {
     "name":"code-compression",
     ...
  }
  ...
}
```

> Example using a custom value
```json
{
 ...
  "structural_features": {
     "name":"some-odd-code-obfuscation",
     ...
  }
  ...
}
```

**Type Name**: `open-vocab`

The `open-vocab` data type is represented as a `string`. For properties that use this type, there will be a list of suggested values to define the property (see [Vocabularies](#Vocabularies)). The value of the property **SHOULD** be chosen from the open vocabulary but **MAY** be any other `string` value. Values that are not from the open vocabulary **SHOULD** be all lowercase (where lowercase is defined by the locality conventions) and **SHOULD** use hyphens instead of spaces or underscores as word separators.

A consumer that receives MAEC content with one or more open-vocab terms not defined in the open vocabulary **MAY** ignore those values.

The JSON MTI serialization uses the JSON string type when representing `open-vocab`.

## String

> String 

```json
{
  ...
  "name":"add-windows-hook",
  ...
}
```
**Type Name**: `string`

The `string` data type represents a finite-length string of valid characters from the Unicode coded character set. Unicode incorporates ASCII and the characters of many other international character sets.

The JSON MTI serialization uses the JSON string type, which mandates the UTF-8 encoding for supporting Unicode.

## Timestamp

> Timestamp 

```json
{
  ...
  "submission_date": "2016-01-20T12:31:12.12345Z",
  ...
}
```
**Type Name**: `timestamp`

The `timestamp` data type defines how timestamps are represented in MAEC.
 
The JSON MTI serialization uses the JSON string type when representing `timestamp`.

*Requirements*:

* A timestamp property **MUST** be a valid RFC 3339-formatted timestamp using the format `YYYY-MM-DDTHH:mm:ss[.s+]Z` where the “s+” represents 1 or more sub-second values. The brackets denote that subsecond precision is optional, and that if no digits are provided, the decimal place **MUST NOT** be present.
* A timestamp **MUST** be represented in the UTC timezone and **MUST** use the “Z” designation to indicate this.

# Vocabularies

## Analysis Conclusions

**Vocabulary Name**: `analysis-conclusion-ov`

The Analysis Conclusion vocabulary is used by the following object/property:

* Malware Instance --> analysis_metadata --> *conclusion*

This vocabulary is an enumeration of conclusions resulting from the analysis of a malware instance.

| Value | Description |
| ----- | ----------- |
| **benign** | As a conclusion of the analysis, the malware instance was determined to be benign.|
| **malicious** | As a conclusion of the analysis, the malware instance was determined to be malicious.|
| **suspicious** | As a conclusion of the analysis, the malware instance was determined to be suspicious.|
| **indeterminate** | The conclusion of the analysis was indeterminate.|


## Analysis Environment

**Vocabulary Name**: `analysis-environment-ov`

The Analysis Environment vocabulary is currently used by the following object/property:

* Malware Instance --> analysis_metadata --> *analysis_environment*

This vocabulary is an enumeration of properties associated with the environment used in malware analysis.

| Value | Description |
| ----- | ----------- |
| **operating-system** | The operating system used for the dynamic analysis of the malware instance. This applies to virtualized operating systems as well as those running on bare metal. The corresponding value for this entry **MUST** be of type `object-ref` and the referenced STIX Cyber Observable Object **MUST** be of type `software`.|
| **host-vm** |The virtual machine used to host the guest operating system (if applicable) used for the the dynamic analysis of the malware instance. If this value is not included in conjunction with `operating-system`, this means that the dynamic analysis was performed on bare metal (i.e., without virtualization). The corresponding value for this entry **MUST** be of type `object-ref` and the referenced STIX Cyber Observable Object **MUST** be of type `software`.|
| **installed-software** | Any non-standard software installed on the operating system (specified through the `operating-system` value) used for the dynamic analysis of the malware instance. The corresponding value for this entry **MUST** be of type `list` and each STIX Cyber Observable Object(s) referenced in the list **MUST** be of type `software`.|


## Analysis Types

**Vocabulary Name**: `analysis-type-ov`

The Analysis Type open vocabulary is used by the following object/property:

* Malware Instance --> analysis_metadata --> *analysis_type* 

This vocabulary is an enumeration of malware analysis types.

| Value | Description |
| ----- | ----------- |
| **static** | Static malware analysis, achieved by inspecting but not executing the malware instance. For example, inspection can be done by studying memory dumps captured after the instance is run.|
| **dynamic** |Dynamic malware analysis, achieved by executing the malware instance (e.g., in a sandbox) and recording its behavior.|
| **combination** | A combination of dynamic and static malware analysis, achieved by both inspecting and executing the malware instance.|


## Behaviors

**Vocabulary Name**: `behavior-ov`

The Behavior open vocabulary is used in the following object/property:

* Behavior --> *name*

This vocabulary is a non-exhaustive enumeration of malware behaviors.

| Value | Description |
| ----- | ----------- |
| **access-premium-service** | Accesses a premium service, such as a premium SMS service.|
| **autonomous-remote-infection** | Infects a remote machine autonomously, without the involvement of any end user (e.g., through the exploitation of a remote procedure call vulnerability).|
| **block-security-websites** | Prevents access from the system on which the malware instance is executing to one or more security vendor or security-related websites.|
| **capture-camera-input** | Captures data from a system's camera, including from embedded cameras (i.e. on mobile devices) and/or attached webcams.|
| **capture-file-system-data** | Captures data from a file system.|
| **capture-gps-data** | Captures GPS data from the system on which the malware instance is executing.|
| **capture-keyboard-input** | Captures data from the keyboard attached to the system on which the malware instance is running.|
| **capture-microphone-input** | Capture data from a system's microphone, including from embedded microphones (i.e. on mobile devices) and those that may be attached externally.|
| **capture-mouse-input** | Captures data from a system's mouse.|
| **capture-printer-output** | Captures data sent to a system's printer, either locally or remotely.|
| **capture-system-memory** | Captures data from a system's RAM.|
| **capture-system-network-traffic** | Captures network traffic from the system on which the malware instance is executing.|
| **capture-system-screenshot** | Captures images of what is currently being displayed on a system's screen, either locally (i.e. on a display) or remotely via a remote desktop protocol.|
| **capture-touchscreen-input** | Captures data from a system's touchscreen.|
| **check-for-payload** | Queries a command and control server to check whether a new payload is available for download.|
| **check-language** | Checks the language of the host system on which it executes.|
| **click-fraud** | Simulates legitimate user clicks on website advertisements for the purpose of revenue generation.|
| **compare-host-fingerprints** | Compares a previously computed host fingerprint to one computed for the current system on which the malware instance is executing, to determine if the malware instance is still executing on the same system.|
| **compromise-remote-machine** | Gains control of a remote machine through compromise, e.g., by exploiting a particular vulnerability.|
| **control-local-machine-via-remote-command** | Controls the machine on which the malware instance is executing, through one or more remotely sent commands.|
| **control-malware-via-remote-command** | Executes commands issued to the malware instance from a remote source such as a command and control server, for the purpose of controlling its behavior.|
| **crack-passwords** | Consumes system resources for the purpose of password cracking.|
| **defeat-call-graph-generation** | Defeats accurate call graph generation during disassembly of the malware instance.|
| **defeat-emulator** | Defeats or prevents the execution of the malware instance in an emulator.|
| **defeat-flow-oriented-disassembler** | Defeats disassembly of the malware instance in a flow-oriented (recursive traversal) disassembler.|
| **defeat-linear-disassembler** | Prevents the disassembly of the malware instance in a linear disassembler.|
| **degrade-security-program** | Degrades one or more security programs running on a system, either by stopping them from executing or by making changes to their code or configuration parameters.|
| **denial-of-service** | Causes the local machine on which the malware instance is executing and/or a remote network resource to be unavailable.|
| **destroy-hardware** | Physically destroys a piece of hardware, e.g., by causing it to overheat.|
| **detect-debugging** | Detects whether the malware instance is being executed inside of a debugger.|
| **detect-emulator** | Detects whether the malware instance is being executed inside of an emulator.|
| **detect-installed-analysis-tools** | Indicates that the malware instance attempts to detect whether certain analysis tools are present on the system on which it is executing.|
| **detect-installed-av-tools** | Indicates that the malware instance attempts to detect whether certain anti-virus tools are present on the system on which it is executing.|
| **detect-sandbox-environment** | Detects whether the malware instance is being executed in a sandbox environment.|
| **detect-vm-environment** | Detects whether the malware instance is being executed in a virtual machine (VM).|
| **determine-host-ip-address** | Determines the IP address of the host system on which the malware instance is executing.|
| **disable-access-rights-checking** | Bypasses, disables, or modifies access tokens or access control lists, thereby enabling the malware instance to read, write, or execute a file with one or more of these controls set.|
| **disable-firewall** | Evades or disables the host-based firewall running on the system on which the malware instance is executing.|
| **disable-kernel-patch-protection** | Bypasses or disables kernel patch protection mechanisms such as Windows' PatchGuard, enabling the malware instance to operate at the same level as the operating system kernel and kernel mode drivers (KMD).|
| **disable-os-security-alerts** | Disables operating system (OS) security alert messages that could lead to identification and/or notification of the presence of the malware instance.|
| **disable-privilege-limiting** | Bypasses or disables mechanisms that limit the privileges that can be granted to a user or entity.|
| **disable-service-pack-patch-installation** | Disables the system's ability to install service packs and/or patches.|
| **disable-system-file-overwrite-protection** | Disables system file overwrite protection mechanisms such as Windows file protection, thereby enabling system files to be modified or replaced.|
| **disable-update-services-daemons** | Disables system update services or daemons that may be already be running on the system on which the malware instance is executing.|
| **disable-user-account-control** | Bypasses or disables Windows' user account control (UAC), enabling the malware instance and/or its component to execute with elevated privileges.|
| **drop-retrieve-debug-log-file** | Generates and retrieves a log file of errors relating to the execution of the malware instance.|
| **elevate-privilege** | Elevates the privilege level under which the malware instance is executing.|
| **encrypt-data** | Encrypts data that will be exfiltrated.|
| **encrypt-files** | Encrypts one or more files on the system on which the malware instance is executing, to make them unavailable for use by the users of the system.|
| **encrypt-self** | Encrypts the executing code (in memory) that belongs to the malware instance.|
| **erase-data** | Destroys data stored on a disk or in memory by erasure.|
| **evade-static-heuristic** | Evades a static anti-virus heuristic. For example, an heuristic engine can try to figure out if a file are using a dual extension (e.g: invoice.doc.exe) and determine the file as being malicious.|
| **execute-before-external-to-kernel-hypervisor** | Executes some or all of the malware instance's code before or external to the system's kernel or hypervisor (e.g., through the BIOS).|
| **execute-non-main-cpu-code** | Executes some or all of the code of the malware instance on a secondary, non-CPU processor (e.g., a GPU).|
| **execute-stealthy-code** | Executes code in a hidden manner (e.g., by injecting it into a benign process).|
| **exfiltrate-data-via-covert channel** | Exfiltrates data using a covert channel, such as a DNS tunnel or NTP.|
| **exfiltrate-data-via- -dumpster-dive** | Exfiltrates data via dumpster dive - i.e, encoded data printed by malware is viewed as garbage and thrown away to then be physically picked up.|
| **exfiltrate-data-via-fax** | Exfiltrates data using a fax system.|
| **exfiltrate-data-via-network** | Exfiltrates data through the computer network connected to the system on which the malware instance is executing.|
| **exfiltrate-data-via-physical-media** | Exfiltrates data by writing it to physical media (e.g., to a USB flash drive).|
| **exfiltrate-data-via-voip-phone** | Exfiltrates data (encoded as audio) using a phone system, such as through voice over IP (VoIP).|
| **feed-misinformation-during-physical-memory-acquisition** | Reports inaccurate data when the contents of the physical memory of the system on which the malware instance is executing is retrieved.|
| **file-system-instantiation** | Indicates that the malware instance instantiates itself on the file system of the machine that it is infecting, in one or more locations.|
| **fingerprint-host** | Creates a unique fingerprint for the system on which the malware instance is executing, e.g., based on the applications that are installed on the system.|
| **generate-c2-domain-names** | Generates the domain name of the command and control server to which the malware connects to.|
| **hide-arbitrary-virtual-memory** | Hides arbitrary segments of virtual memory belonging to the malware instance in order to prevent their retrieval.|
| **hide-data-in-other-formats** | Hides data that will be exfiltrated in other formats (e.g., image files).|
| **hide-file-system-artifacts** | Hides one or more file system artifacts (e.g., files and/or directories) associated with the malware instance.|
| **hide-kernel-modules** | Hides the usage of any kernel modules by the malware instance.|
| **hide-network-traffic** | Hides network traffic associated with the malware instance.|
| **hide-open-network-ports** | Hides one or more open network ports associated with the malware instance.|
| **hide-processes** | Hides one or more of the processes in which the malware instance is executing.|
| **hide-registry-artifacts** | Hides one or more Windows registry artifacts (e.g., keys and/or values) associated with the malware instance.|
| **hide-services** | Hides any system services that the malware instance creates or injects itself into.|
| **hide-threads** | Hides one or more threads that belong to the malware instance.|
| **hide-userspace-libraries** | Hides the usage of userspace libraries by the malware instance.|
| **identify-file** | Identifies one or more files on a local, removable, and/or network drive for infection.|
| **identify-os** | Identifies the operating system under which the malware instance is executing.|
| **identify-target-machines** | Identifies one or more machines to be targeted for infection via some remote means (e.g., via email or the network).|
| **impersonate-user** | Impersonates another user in order to operate within a different security context.|
| **install-backdoor** | Installs a backdoor on the system on which the malware instance is executing, capable of providing covert remote access to the system.|
| **install-legitimate-software** | Installs legitimate (i.e. non-malware) software on the same system on which the malware instance is executing.|
| **install-secondary-malware** | Installs another, different malware instance on the system on which the malware instance is executing.|
| **install-secondary-module** | Installs a secondary module (typically related to the malware instance itself) on the same system on which the malware instance is executing.|
| **intercept-manipulate-network-traffic** | Intercepts and/or manipulates network traffic going to or originating from the system on which the malware instance is executing.|
| **inventory-security-products** | Creates an inventory of the security products installed or running on a system.|
| **inventory-system-applications** | Inventories the applications installed on the system on which the malware instance is executing.|
| **inventory-victims** | Keeps an inventory of the victims that are remotely infected by the malware instance.|
| **limit-application-type-version** | Limits the type or version of an application that runs on a system in order to ensure that the malware instance is able to continue executing.|
| **log-activity** | Logs the activity of the malware instance.|
| **manipulate-file-system-data** | Manipulates data stored on the file system of the system on which the malware instance is executing in order to compromise its integrity.|
| **map-local-network** | Maps the layout of the local network environment in which the malware instance is executing.|
| **mine-for-cryptocurrency** | Consumes system resources for cryptocurrency (e.g., Bitcoin, Litecoin, etc.) mining.|
| **modify-file** | Modifies a file in some other manner than writing code to it, such as packing it (in terms of binary executable packing).|
| **modify-security-software-configuration** | Modifies the configuration of one or more instances of security software (e.g., anti-virus) running on a system in order to negatively impact their usefulness and ability to detect the malware instance.|
| **move-data-to-staging-server** | Moves data to be exfiltrated to a particular server, to prepare it for exfiltration.|
| **obfuscate-artifact-properties** | Hides the properties of one or more artifacts associated with the malware instance (e.g., by altering file system timestamps).|
| **overload-sandbox** | Overloads a sandbox (e.g., by generating a flood of meaningless behavioral data).|
| **package-data** | Packages data for exfiltration, e.g., by adding it to an archive file.|
| **persist-after-hardware-changes** | Continues the execution of the malware instance after hardware changes to the system on which it is executing have been made, such as replacement of the hard drive on which the operating system was residing.|
| **persist-after-os-changes** | Continues the execution of the malware instance after the operating system under which it is executing is modified, such as being installed or reinstalled.|
| **persist-after-system-reboot** | Continues the execution of the malware instance after a system reboot.|
| **prevent-api-unhooking** | Prevents the API hooks installed by the malware instance from being removed.|
| **prevent-concurrent-execution** | Checks to see if it is already running on a system, in order to prevent multiple instances of the malware running concurrently.|
| **prevent-debugging** | Prevents the execution of the malware instance in a debugger.|
| **prevent-file-access** | Prevents access to the file system, including to specific files and/or directories associated with the malware instance.|
| **prevent-file-deletion** | Prevents files and/or directories associated with the malware instance from being deleted from a system.|
| **prevent-memory-access** | Prevents access to system memory where the malware instance may be storing code or data.|
| **prevent-native-api-hooking** | Prevents other software from hooking native system APIs.|
| **prevent-physical-memory-acquisition** | Prevents the contents of the physical memory of the system on which the malware instance is executing from being retrieved.|
| **prevent-registry-access** | Prevents access to the Windows registry, including to the entire registry and/or to particular registry keys/values.|
| **prevent-registry-deletion** | Prevent Windows registry keys and/or values associated with the malware instance from being deleted from a system.|
| **prevent-security-software- -from-executing** | Prevents one or more instances of security software from executing on a system.|
| **re-instantiate-self** | Re-establishes the malware instance on the system after it is initially detected and partially removed.|
| **remove-self** | Removes the malware instance from the system on which it is executing.|
| **remove-sms-warning-messages** | Captures the message body of incoming SMS messages and aborts displaying messages that meets a certain criteria.|
| **remove-system-artifacts** | Removes artifacts associated with the malware instance (e.g., files, directories, Windows registry keys, etc.) from the system on which it is executing.|
| **request-email-address-list** | Requests the current list of email addresses, for sending email spam messages to, from the command and control server.|
| **request-email-template** | Requests the current template, for use in generating email spam messages, from the command and control server.|
| **search-for-remote-machines** | Searches for one or more remote machines to target.|
| **send-beacon** | Sends 'beacon' data to a command and control server, indicating that the malware instance is still active on the host system and able to communicate.|
| **send-email-message** | Sends an email message from the system on which the malware instance is executing to one or more recipients, most commonly for the purpose of spamming.|
| **send-system-information** | Sends data regarding the system on which it is executing to a command and control server.|
| **social-engineering-based-remote-infection** | Infects remote machines via some method that involves social engineering (e.g., sending an email with a malicious attachment).|
| **steal-browser-cache** | Steals a user's browser cache.|
| **steal-browser-cookies** | Steals one or more browser cookies stored on the system on which the malware instance is executing.|
| **steal-browser-history** | Steals a user's browser history.|
| **steal-contact-list-data** | Steals a user's contact list.|
| **steal-cryptocurrency-data** | Steals cryptocurrency data that may be stored on a system (e.g., Bitcoin wallets).|
| **steal-database-content** | Steals content from a database that the malware instance may be able to access.|
| **steal-dialed-phone-numbers** | Steals the list of phone numbers that a user has dialed (i.e. on a mobile device).|
| **steal-digital-certificates** | Steals one or more digital private keys that may be present on the system on which the malware instance is executing, to then use to hijack the corresponding digital certificates, e.g., those used in public-key infrastructure (PKI).|
| **steal-documents** | Steals document files (e.g., PDF) stored on a system.|
| **steal-email-data** | Steals a user's email data.|
| **steal-images** | Seals image files that may be stored on a system.|
| **steal-password-hashes** | Steals password hashes.|
| **steal-pki-key** | Steals one or more public key infrastructure (PKI) keys.|
| **steal-referrer-urls** | Steals HTTP referrer information (URL of the webpage that linked to the resource being requested).|
| **steal-serial-numbers** | Steals serial numbers stored on a system.|
| **steal-sms-database** | Steals a user's short message service (SMS) (text messaging) database (i.e. on a mobile device).|
| **steal-web-network-credential** | Steals usernames, passwords, or other forms of web (e.g., for logging into a website) and/or network credentials.|
| **stop-execution-of-security-software** | Stops the execution of one or more instances of security software that may already be executing on a system.|
| **suicide-exit** | Terminates the execution of the malware instance based on some trigger condition or value.|
| **test-for-firewall** | Tests whether the network environment in which the malware instance is executing contains a hardware or software firewall.|
| **test-for-internet-connectivity** | Tests whether the network environment in which the malware instance is executing is connected to the internet.|
| **test-for-network-drives** | Tests for network drives that may be present in the network environment in which the malware instance is executing.|
| **test-for-proxy** | Tests whether the network environment in which the malware instance is executing contains a hardware or software proxy.|
| **test-smtp-connection** | Tests whether an outgoing SMTP connection can be made from the system on which the malware instance is executing to some SMTP server, by sending a test SMTP transaction.|
| **update-configuration** | Updates the configuration of the malware instance using data received from a command and control server.|
| **validate-data** | Validates the integrity of data received from a command and control server.|
| **write-code-into-file** | Writes code into one or more files.|

## Capabilities

**Vocabulary Name**: `capability-ov`

The Malware Capability open vocabulary is used in the following object/property:

* Capability --> *name*

| Value | Description |
| ----- | ----------- |
|**anti-behavioral-analysis** | Indicates that the malware instance or family is able to prevent behavioral analysis or make it more difficult.|
|**anti-code-analysis** | Indicates that the malware instance or family is able to prevent code analysis or make it more difficult.|
|**anti-detection** | Indicates that the malware instance or family is able to prevent itself and its components from being detected on a system.|
|**anti-removal** | Indicates that the malware instance or family is able to prevent itself and its components from being removed from a system.|
|**availability-violation** | Indicates that the malware instance or family is able to compromise the availability of a system or some aspect of the system.|
|**collection** | "Indicates that the malware instance or family is able to capture information from a system related to user or system activity (e.g., from a system's peripheral devices)."|
|**command-and-control** | Indicates that the malware instance or family is able to receive and/or execute remotely submitted commands.|
|**data-theft** | "Indicates that the malware instance or family is able to steal data from the system on which it executes. This includes data stored in some form, e.g. in a file, as well as data that may be entered into some application such as a web-browser."|
|**destruction** | Indicates that the malware instance or family is able to destroy some aspect of a system.|
|**discovery** | Indicates that the malware instance or family is able to probe its host system or network environment; most often this is done to support other Capabilities and their Objectives.|
|**exfiltration** | Indicates that the malware instance or family is able to exfiltrate stolen data or perform tasks related to the exfiltration of stolen data.|
|**fraud** | Indicates that the malware instance or family is able to defraud a user or a system.|
|**infection-propagation** | "Indicates that the malware instance or family is able to propagate through the infection of a machine or is able to infect a file after executing on a system. The malware instance may infect actively (e.g., gain access to a machine directly) or passively (e.g., send malicious email). This Capability does not encompass any aspects of the initial infection that is done independently of the malware instance itself."|
|**integrity-violation** | Indicates that the malware instance or family is able to compromise the integrity of a system.|
|**machine-access-control** | Indicates that the malware instance or family is able to access or control one or more remote machines and/or the machine on which it is executing.|
|**persistence** | Indicates that the malware instance or family is able to persist and remain on a system regardless of system events.|
|**privilege-escalation** | Indicates that the malware instance or family is able to elevate the privileges under which it executes.|
|**secondary-operation** | Indicates that the malware instance or family is able to achieve secondary objectives in conjunction with or after achieving its primary objectives.|
|**security-degradation** | Indicates that the malware instance or family is able to bypass or disable security features and/or controls.|


## Common Attributes

**Vocabulary Name**: `common-attribute-ov`

The Common Attribute open vocabulary is used in the following objects/properties:

* Capability --> *attributes*
* Behavior --> *attributes*

This vocabulary is a non-exhaustive enumeration of common attributes associated with Capabilities or Behaviors of a Malware Instance or Malware Family.

| Value | Description |
| ----- | ----------- |
|**applicable-platform** | Captures the name of a targeted platform.| 
|**archive-type** | Captures the name of a file archive format used.|
|**autonomy** | Captures the level of autonomy used.| 
|**backdoor-type** | Captures the type of backdoor used.| 
|**cryptocurrency-type** | Captures a cryptocurrency targeted.| 
|**encryption-algorithm** | Captures the encryption algorithm used.| 
|**erasure-scope** | Captures the scope of the erasure performed.| 
|**file-infection-type** | Captures the method that an executable infector uses to infect a file.| 
|**file-modification-type** | Captures how a malware file modifies itself to avoid detection.| 
|**file-type** | Captures the type of file format used for storing data to be exfiltrated.|
|**frequency** | "Captures the frequency with which a C2 Server sends and receives data.| It is recommended that the description follow the format of "every x (units)", e.g., "every 5 minutes."|
|**infection-targeting** | "Captures the type of targeting employed, e.g., whether the targeted machines are randomly selected, or chosen from some particular set.| "
|**network-protocol** | "Captures the name of the network protocol used in command and control communications.| The protocol name **MUST** come from the service names defined in the Service Name column of the IANA Service Name and Port Number Registry.| In cases where an there is variance in the name of a network protocol not included in the IANA Registry, content producers should exercise their best judgement, and it is recommended that lowercase names be used for consistency with the IANA registry.|"
|**port-number** | Captures the port number used in command and control communications.|
|**persistence-scope** | Captures the scope of persistence employed.| 
|**propagation-scope** | "Captures the scope of the infection or propagation performed, i.|e.|, whether it infects just the local machine or actively propagates to other machines as well.| "
|**targeted-application** | Captures the names of any targeted applications.|
|**targeted-file-architecture type** | Captures the types of file architectures targeted.|
|**targeted-file-type** | Captures the types of files targeted.| 
|**targeted-program** | Captures the names of any targeted programs.| 
|**targeted-sandbox** | Captures the names of any sandboxes targeted.| 
|**targeted-vm** | Captures the names of any virtual machines (VM) targeted.| 
|**targeted-website** | Captures the domain names of any targeted websites.| 
|**technique** | Captures the name of the technique used.| 
|**trigger-type** | Captures the trigger used to wake or terminate the malware instance.| 
|**user-privilege-escalation type** | Captures the type of user privilege escalation employed.| 
|**vulnerability-id-cve** | Captures the Common Vulnerabilities and Exposures (CVE) vulnerability identifier being referenced.|
|**vulnerability-id-osvdb** | Captures the vulnerability identifier of the Open Source Vulnerability Database (OSVDB) entry being referenced.|


## Delivery Vectors

**Vocabulary Name**: `delivery-vector-ov`

The Delivery Vector open vocabulary is used in the following objects/properties:

* Malware Instance --> field_data --> *delivery_vectors* 
* Malware Family --> field_data --> *delivery_vectors* 

This vocabulary is a non-exhaustive enumeration of vectors used to deliver malware.

| Value | Description |
| ----- | ----------- |
| **active-attacker** | The malware instance or family was delivered via an active attacker.|
| **auto-executing-media** | The malware instance or family was delivered via media that automatically executes.|
| **downloader** | The malware instance or family was delivered via downloader.|
| **dropper** | The malware instance or family was delivered via dropper.|
| **email-attachment** | The malware instance or family was delivered via email attachment.|
| **exploit-kit-landing-page** | The malware instance or family was delivered via an exploit kit landing page.|
| **fake-website** | The malware instance or family was delivered via a fake website.|
| **janitor-attack** | The malware instance or family was delivered via a janitor attack.|
| **malicious-iframes** | The malware instance or family was delivered via malicious iframes.|
| **malvertising** | The malware instance or family was delivered via malvertising.|
| **media-baiting** | The malware instance or family was delivered via media baiting.|
| **pharming** | The malware instance or family was delivered via pharming.|
| **phishing** | The malware instance or family was delivered via phishing.|
| **trojanized-link** | The malware instance or family was delivered via a trojanized link.|
| **trojanized-software** | The malware instance or family was delivered via trojanized software.|
| **usb-cable-syncing** | The malware instance or family was delivered via usb cable syncing.|
| **watering-hole** | The malware instance or family was delivered via a watering hole.|


## Entity Associations

**Vocabulary Name**: `entity-association-ov`

The Entity Association open vocabulary is used in the following object/property:

* Collection --> *association_type*

This vocabulary is an non-exhaustive enumeration of entity association types relevant to MAEC entities and STIX Cyber Observables.

| Value | Description |
| ----- | ----------- |
| **file-system-entities** | The collection contains Cyber Observable Objects that correspond to file system entities.|
| **network-entities** | The collection contains Cyber Observable Objects that correspond to network entities.|
| **process-entities** | The collection contains Cyber Observable Objects that correspond to process entities.|
| **memory-entities** | The collection contains Cyber Observable Objects that correspond to memory entities.|
| **ipc-entities** | The collection contains Cyber Observable Objects that correspond to inter-process communication (IPC) entities.|
| **device-entities** | The collection contains Cyber Observable Objects that correspond to device entities.|
| **registry-entities** | The collection contains Cyber Observable Objects that correspond to registry entities.|
| **service-entities** | The collection contains Cyber Observable Objects that correspond to service entities.|
| **potential-indicators** | The collection contains entities that serve as potential indicators.|
| **same-malware-family** | The collection contains that Malware Instances are from the same malware family.|
| **clustered-together** | The collection contains Malware Instances that have been clustered together by some method such as a scoring algorithm.|
| **observed-together** | The collection contains Malware Instances that have been observed together.|
| **same-malware-toolkit** | The collection contains Malware Instances that are derived from the same malware toolkit.|


## Malware Actions

**Vocabulary Name**: `malware-action-ov`

The Malware Action open vocabulary is used in the following object/property:

* Malware Action --> *name*

This vocabulary is a non-exhaustive enumeration of Actions that may be performed by a Malware Instance.

| Value | Description |
| ----- | ----------- |
|**accept-socket-connection** | The action of accepting a socket connection.|
|**add-connection-to-network-share** | The action of adding a connection to a network share.|
|**add-network-share** | The action of adding a new network share on a server.|
|**add-scheduled-task** | The action of adding a scheduled task to a system.|
|**add-system-call-hook** | The action of adding a new system call hook.|
|**add-user-to-group** | The action of adding an existing user to a group.|
|**add-user** | The action of adding a new user.|
|**add-windows-hook** | The action of adding a new Windows application-defined hook procedure.|
|**allocate-process-virtual-memory** | The action of allocating a virtual memory region in an existing process.|
|**bind-address-to-socket** | The action of binding a socket address to a socket.|
|**call-library-function** | The action of calling a function exported by a library.|
|**change-password** | The action of changing a user’s password.|
|**check-for-kernel-debugger** | The action of checking for the presence of a kernel debugger.|
|**check-for-remote-debugger** | The action of checking for the presence of a remote debugger.|
|**close-file** | The action of closing an existing file previously opened for reading or writing.|
|**close-port** | The action of closing a network port.|
|**close-registry-key** | The action of closing a handle to an existing registry key.|
|**close-socket** | The action of closing a socket.|
|**connect-to-ftp-server** | The action of connecting to an ftp server.|
|**connect-to-ip-address** | The action of connecting to an IP address.|
|**connect-to-irc-server** | The action of connecting to an IRC server.|
|**connect-to-named-pipe** | The action of connecting to a named pipe.|
|**connect-to-network-share** | The action of connecting to a network share.|
|**connect-to-socket-address** | The action of connecting to a socket address.|
|**connect-to-socket** | "The action of connecting to a socket, which consists of an IP address and port number.|"
|**connect-to-url** | The action of connecting to a URL.|
|**copy-file** | The action of copying a file from one location to another.|
|**create-critical-section** | The action of creating a new critical section.|
|**create-dialog-box** | The action of creating a new dialog box.|
|**create-directory** | The action of creating a new directory.|
|**create-event** | The action of creating a new event.|
|**create-file-alternate-data-stream** | The action of creating a new file alternate data stream in a file.|
|**create-file-mapping** | The action of creating a new file mapping object.|
|**create-file-symbolic-link** | The action of creating a new symbolic link to a file.|
|**create-file** | The action of creating a new file.|
|**create-mailslot** | The action of creating a new mailslot.|
|**create-mutex** | The action of creating a new mutex.|
|**create-named-pipe** | The action of creating a new named pipe.|
|**create-process-as-user** | The action of creating a new process as a particular user.|
|**create-process** | The action of creating a new process.|
|**create-registry-key-value** | The action of creating a new registry key value.|
|**create-registry-key** | The action of creating a new registry key.|
|**create-remote-thread-in-process** | The action of creating a new thread that runs in the virtual address space of another process.|
|**create-semaphore** | The action of creating a new named semaphore.|
|**create-service** | The action of creating a new service.|
|**create-socket** | The action of creating a new socket.|
|**create-thread** | The action of creating a new thread.|
|**create-window** | The action of creating a new window.|
|**delete-critical-section** | The action of deleting a critical section object.|
|**delete-directory** | The action of deleting a directory on a filesystem.|
|**delete-event** | The action of deleting a named event object.|
|**delete-file** | The action of deleting a file.|
|**delete-mutex** | The action of deleting a named mutex.|
|**delete-named-pipe** | The action of deleting a named pipe.|
|**delete-network-share** | The action of deleting a network share on a server.|
|**delete-registry-key-value** | The action of deleting a named value under an existing registry key.|
|**delete-registry-key** | The action of deleting a registry key.|
|**delete-semaphore** | The action of deleting a named semaphore.|
|**delete-service** | The action of deleting a service.|
|**delete-user** | The action of deleting a user.|
|**disconnect-from-ftp-server** | The action of disconnecting from a FTP server.|
|**disconnect-from-ip** | The action of disconnecting from a previously established connection to an IP address.| 
|**disconnect-from-irc-server** | The action of disconnecting from an IRC server.|
|**disconnect-from-named-pipe** | The action of disconnecting from a named pipe.|
|**disconnect-from-network-share** | The action of disconnecting from a network share.|
|**disconnect-from-socket** | The action of disconnecting from a socket.|
|**download-file** | The action of downloading a file from a remote location.|
|**enumerate-libraries** | The action of enumerating the libraries used by a process.|
|**enumerate-network-shares** | The action of enumerating the available shared resources on a server.|
|**enumerate-processes** | The action of enumerating all of the running processes on a system.|
|**enumerate-registry-key-subkeys** | The action of enumerating the registry key subkeys under a registry key.|
|**enumerate-registry-key-values** | The action of enumerating the named values under a registry key.|
|**enumerate-services** | The action of enumerating a specific set of services on a system.|
|**enumerate-system-handles** | The action of enumerating all open handles on a system.|
|**enumerate-threads** | The action of enumerating all threads in the calling process.|
|**enumerate-users** | The action of enumerating all users.|
|**enumerate-windows** | The action of enumerating all open windows.|
|**execute-file** | The action of executing a file.|
|**find-file** | The action of searching for a file.|
|**find-window** | The action of searching for a window.|
|**flush-process-instruction-cache** | The action of flushing the instruction cache of a process.|
|**free-library** | The action of freeing a library previously loaded into the address space of the calling process.|
|**free-process-virtual-memory** | The action of freeing virtual memory regions from a process.|
|**get-disk-attributes** | "The action of querying the attributes of a disk, such as the amount of available free space.|"
|**get-disk-type** | The action of getting the disk type.|
|**get-elapsed-system-up-time** | The action of getting the elapsed up-time for a system.|
|**get-file-or-directory-attributes** | The action of getting the attributes of a file or directory.|
|**get-function-address** | The action of getting the address of an exported function or variable from a library.|
|**get-host-by-address** | The action of getting information on a host from a local or remote host database by its IP address.|
|**get-host-by-name** | The action of getting information on a host from a local or remote host database by its name.|
|**get-netbios-name** | The action of getting the NetBIOS name of a system.|
|**get-process-current-directory** | The action of getting the current directory of a process.|
|**get-process-environment-variable** | The action of setting an environment variable used by a process.|
|**get-process-startupinfo** | The action of getting the STARTUPINFO struct associated with a process.|
|**get-registry-key-attributes** | The action of getting the attributes of a registry key.|
|**get-system-global-flags** | The action of getting the enabled global flags on a system.|
|**get-system-host-name** | The action of getting the hostname of a system.|
|**get-system-local-time** | The action of getting the local time of a system.|
|**get-system-time** | "The action of getting the system time of a system, represented in Coordinated Universal Time (UTC).|"
|**get-thread-context** | The action of getting the context structure (containing process-specific register data) of a thread.|
|**get-thread-username** | The action of getting the name or ID of the user associated with a thread.|
|**get-user-attributes** | The action of getting the attributes of a user.|
|**get-username** | The action of getting the username of the currently logged in user of a system.|
|**get-windows-directory** | The action of getting the Windows installation directory on a system.|
|**get-windows-system-directory** | The action of getting the Windows \System or \System32 directory on a system.|
|**get-temporary-files-directory** | The action of getting the temporary file directory on a system.|
|**impersonate-process** | The action of a thread in the calling process impersonating the security context of another process.|
|**invoke-user-privilege** | The action of invoking a privilege given to an existing user.|
|**join-irc-channel** | The action of joining a channel on an IRC server.|
|**kill-process** | The action of killing a process.|
|**kill-thread** | The action of killing a thread in the virtual address space of the calling process.|
|**kill-window** | The action of killing a window.|
|**leave-irc-channel** | The action of leaving a channel on an IRC server.|
|**enumerate-disks** | The action of listing all disks available on a system.|
|**listen-on-port** | The action of listening on a specific port.|
|**listen-on-socket** | The action of listening on a socket.|
|**load-and-call-driver** | The action of loading a driver into a system and then calling the loaded driver.|
|**load-driver** | The action of loading a driver into a system.|
|**load-library** | The action of loading a library into the address space of the calling process.|
|**lock-file** | The action of locking a file.|
|**logon-as-user** | The action of logging on as a specific user.|
|**map-file-into-process** | The action of mapping a file into the address space of the calling process.|
|**map-library-into-process** | The action of mapping a library into the address space of the calling process.|
|**modify-process-virtual-memory-protection** | The action of modifying the protection on a memory region in the virtual address space of a process.|
|**modify-registry-key-value** | The action of modifying a named value of a registry key.|
|**modify-registry-key** | The action of modifying a registry key.|
|**modify-service-configuration** | The action of modifying the configuration parameters of a service.| 
|**monitor-directory** | The action of monitoring a directory on the filesystem for changes.|
|**monitor-disk** | The action of monitoring a disk for changes.|
|**monitor-registry-key** | The action of monitoring a registry key for changes.|
|**mount-disk** | The action of mounting a file system to a mounting point.|
|**move-file** | The action of moving a file from one location to another.|
|**open-critical-section** | The action of opening a critical section object.|
|**open-event** | The action of opening a named event object.|
|**open-file-mapping** | The action of opening a file mapping object.|
|**open-directory** | The action of opening a directory.|
|**open-file** | The action of opening a file for reading or writing.|
|**open-mutex** | The action of opening a named mutex.|
|**open-port** | The action of opening a network port.|
|**open-process** | The action of opening a process.|
|**open-registry-key** | The action of opening a registry key.|
|**open-semaphore** | The action of opening a named semaphore.|
|**open-service** | The action of opening a service.|
|**queue-apc-in-thread** | The action of queuing a new Asynchronized Procedure Call (APC) in the context of a thread.| 
|**read-from-file** | The action of reading from a file.|
|**read-from-mailslot** | The action of reading some data from a named mailslot.|
|**read-from-named-pipe** | The action of reading data from a named pipe.|
|**read-from-process-memory** | The action of reading from a memory region of a process.|
|**read-registry-key-value** | The action of reading a named value of a registry key.|
|**receive-data-on-socket** | The action of receiving data on a socket.|
|**receive-http-response** | The action of receiving an HTTP server response for a prior HTTP request.|
|**receive-irc-private-message** | The action of receiving a private message from another user on an IRC server.|
|**receive-network-packet** | The action of receiving a packet on a network.|
|**release-critical-section** | The action of releasing a critical section object.|
|**release-mutex** | The action of releasing ownership of a named mutex.|
|**release-semaphore** | The action of releasing ownership of a named semaphore.|
|**remove-user-from-group** | The action of removing a user from a group.|
|**rename-file** | The action of renaming a file on a file system.|
|**reset-event** | The action of resetting a named event object to the non-signaled state.|
|**revert-thread-to-self** | The action of reverting a thread to its own security context.|
|**send-control-code-to-file** | The action of sending a control code to a file.|
|**send-control-code-to-service** | The action of sending a control code to a service.|
|**send-data-on-socket** | The action of sending data on a connected socket.|
|**send-data-to-address-on-socket** | The action of sending data to a specified IP address on an unconnected socket.|
|**send-dns-query** | The action of sending a DNS query.|
|**send-email-message** | The action of sending an email message.|
|**send-ftp-command** | The action of of sending a command on an FTP server connection.|
|**send-http-connect-request** | The action of sending an HTTP CONNECT client request to a server.|
|**send-http-delete-request** | The action of sending an HTTP DELETE client request.|
|**send-http-get-request** | The action of sending an HTTP GET client request.|
|**send-http-head-request** | The action of sending an HTTP HEAD client request.|
|**send-http-options-request** | The action of sending an HTTP OPTIONS client request.|
|**send-http-patch-request** | The action of sending an HTTP PATCH client request.|
|**send-http-post-request** | The action of sending an HTTP HEAD client request.|
|**send-http-put-request** | The action of sending an HTTP PUT client request.|
|**send-http-trace-request** | The action of sending an HTTP TRACE client request.|
|**send-icmp-request** | The action of sending an ICMP request.|
|**send-irc-private-message** | The action of sending a private message to another user on an IRC server.|
|**send-network-packet** | The action of sending a packet on a network.|
|**send-reverse-dns-lookup** | The action of sending a reverse DNS lookup.|
|**set-file-or-directory-attributes** | The action of setting some attributes on a file or directory.|
|**set-irc-nickname** | The action of setting an IRC nickname on an IRC server.|
|**set-netbios-name** | The action of setting the NetBIOS name of a system.|
|**set-process-current-directory** | The action of setting the current directory of a process.|
|**set-process-environment-variable** | The action of setting an environment variable used by a process.|
|**set-system-global-flags** | The action of setting a system’s global flags.|
|**set-system-host-name** | The action of setting a system’s hostname.|
|**set-system-local-time** | The action of setting a system’s local time.|
|**set-system-time** | "The action of setting a system’s time, represented in UTC.|"
|**set-thread-context** | The action of setting the context structure (containing process-specific register data) for a thread.|
|**show-window** | The action of showing a window.|
|**shutdown-system** | The action of shutting down a system.|
|**sleep-process** | The action of sleeping a process for some period of time.|
|**sleep-system** | The action of sleeping a system for some period of time.|
|**start-service** | The action of starting a service.|
|**stop-service** | The action of stopping a service.|
|**unload-driver** | The action of unloading a driver from a system.|
|**unlock-file** | The action of unlocking a file.|
|**unmap-file-from-process** | The action of unmapping a file from the address space of the calling process.|
|**unmount-disk** | The action of unmounting a file system from a mounting point.|
|**upload-file** | The action of uploading a file to a remote location.|
|**write-to-file** | The action of writing data to a file.|
|**write-to-mailslot** | The action of writing data to a named mailslot.|
|**write-to-named-pipe** | The action of writing data to a named pipe.|
|**write-to-process-memory** | The action of writing to a memory region of an existing process.|


## Malware-Configuration-Parameters

**Vocabulary Name**: `malware-configuration-parameter-ov`

The Malware Configuration Parameters open vocabulary is used in the following object/property:

* Malware Instance --> static_features --> *configuration_parameters*

This vocabulary is a non-exhaustive enumeration of malware configuration parameter names.

| Value | Description |
| ----- | ----------- |
| **filename** | Captures the name of a file (e.g., a binary downloaded, embedded binary).|
| **group-id** | Captures an identifier of a collection of malware instances.|
| **id** | Captures an identifier of a malware instance.|
| **installation-path** | Captures a location on disk where the malware instance is installed, copied, or moved.|
| **magic-number** | Captures a file signature used to identify or validate content of the malware instance.|
| **mutex** | Captures a unique mutex value associated with the malware instance.|
| **c2-ip-address** | Captures an IP address used by the malware instance for command and control.|
| **c2-domain** | Captures a domain name used by the malware instance for command and control.|
| **c2-url** | Captures a URL used by the malware instance for command and control.|
| **directory** | Captures the name of a directory used by the malware instance.|
| **filepath** | Captures a file path (directory + file name) used by the malware instance.|
| **injection-process** | Captures a process into which malware instance is injected. Usually this is a process name but it may take other forms such as a filename of the executable.|
| **interval** | Captures the time malware instance waits between beacons or other activity, in seconds.|
| **key** | Captures an encryption, encoding, or obfuscation key used by the malware instance. By convention, when these represent binary data, they should be bare hex encoded with no other markup. Base64 or similar custom dictionaries are stored as is.|
| **password** | Captures a password used by the malware instance.|
| **useragent** | Captures a software identifier used by the malware instance.|
| **version** | Captures the version of the malware instance. To the degree possible this should be based directly on artifacts from the malware.|


## Malware Labels

**Vocabulary Name**: `malware-label-ov`

The malware label vocabulary is currently used in the following objects/properties:

* Malware Instance --> *labels*
* Malware Family --> *labels*

This vocabulary is a non-exhaustive enumeration of common malware labels.

| Value | Description |
| ----- | ----------- |
| **adware** | Any software that is funded by advertising. Adware may also gather sensitive user information from a system.|
| **appender** | File-infecting malware that places its code at the end of the files it infects, adjusting the file's entry point to cause its code to be executed before that in the original file.|
| **backdoor** | Malware which, once running on a system, opens a communication vector to the outside so the computer can be accessed remotely by an attacker.|
| **boot-sector-virus** | Malware that infects the master boot record of a storage device.|
| **bot** | Malware that resides on an infected system, communicating with and forming part of a botnet. The bot may be implanted by a worm or trojan, which opens a backdoor. The bot then monitors the backdoor for further instructions.|
| **cavity-filler** | A type of file-infecting virus that seeks unused space within the files it infects, inserting its code into these gaps to avoid changing the size of the file and thus not alerting integrity-checking software to its presence.|
| **clicker** | A trojan that makes a system visit a specific web page, often very frequently and usually with the aim of increasing the traffic recorded by the site and thus increasing revenue from advertising. Clickers may also be used to carry out DDoS attacks.|
| **companion-virus** | A virus that takes the place of a particular file on a system instead of injecting code into it.|
| **data-diddler** | A type of malware that makes small, random changes to data, such as data in a spreadsheet, to render the data contained in a document inaccurate and in some cases worthless.|
| **ddos** | A tool used to perform a distributed denial of service attack.|
| **downloader** | Malware programmed to download and execute other files, usually more complex malware.|
| **dropper** | A type of Trojan that deposits an enclosed payload onto a destination host computer by loading itself into memory, extracting the malicious payload, and then writing it to the file system.|
| **exploit-kit** | A software toolkit to target common vulnerabilities.|
| **file-infector-virus** | A virus that infects a system by inserting itself somewhere in existing files; this is the classic form of virus.|
| **file-less** | Malware that is file-less, i.e., executes through some other mechanism such as Powershell.|
| **fork-bomb** | A simple form of malware, a type of rabbit which launches more copies of itself. Once a fork bomb is executed, it will attempt to run several identical processes, which will do the same, the number growing exponentially until the system resources are overwhelmed by the number of identical processes running, which may in some cases bring the system down and cause a denial of service.|
| **greyware** | Software that, while not definitely malicious, has a suspicious or potentially unwanted aspect.|
| **implant** | Code inserted into an existing program using a code patcher or other tool.|
| **keylogger** | A type of program implanted on a system to monitor the keys pressed and thus record any sensitive data, such as passwords, entered by the user.|
| **kleptographic-worm** | A worm that encrypts information assets on compromised systems so they can only be decrypted by the worm's author, also known as information-stealing worm.|
| **macro-virus** | A virus that uses a macro language, for example in Microsoft Office documents.|
| **malware-as-a-service** | Malware that is sold or produced as a service.|
| **mass-mailer** | A worm that uses email to propagate across the internet.|
| **metamorphic-virus** | A virus that changes its own code with each infection.|
| **mid-infector** | A type of file-infecting virus which places its code in the middle of files it infects. It may move a section of the original code to the end of the file, or simply push the code aside to make space for its own code.|
| **mobile-code** | Either code received from remote, possibly untrusted systems, but executed on a local system; or software transferred between systems (e.g across a network) and executed on a local system without explicit installation or execution by the recipient.|
| **multipartite-virus** | Malware that infects boot records, boot sectors, and files.|
| **parental-control** | A program that monitors or limits machine usage. Such programs can run undetected and can transmit monitoring information to another machine.|
| **password-stealer** | A type of trojan designed to steal passwords, personal data and details, or other sensitive information from an infected system.|
| **polymorphic-virus** | A type of virus that encrypts its code differently with each infection (or with each generation of infections).|
| **premium-dialer-smser** | A type of malware whose primary aim is to dial (or send SMS messages to) premium rate numbers.|
| **prepender** | A file-infecting virus that inserts code at the beginning of the files it infects.|
| **ransomware** | Malware that encrypts files on a victim's system, demanding payment of ransom in return for the access codes required to unlock files.|
| **remote-access-trojan** | A remote access trojan program (or RAT), is a trojan horse capable of controlling a machine through commands issued by a remote attacker.|
| **resource-exploiter** | A type of malware that steals a system's resources (e.g., CPU cycles), such as a bitcoin miner.|
| **rogue-security-software** | A fake security product that demands money to clean phony infections.|
| **rootkit** | A method of hiding files or processes from normal methods of monitoring; often used by malware to conceal its presence and activities.|
| **scareware** | A program that reports false or significantly misleading information on the presence of security risks, threats, or system issues on the target computer.|
| **screen-capture** | A type of malware used to capture images from the target systems screen, used for exfiltration and command and control.|
| **security-assessment-tool** | A program that can be used to gather information for unauthorized access to computer systems.|
| **shellcode** | Either a small piece of code that activates a command-line interface to a system that can be used to disable security measures, open a backdoor, or download further malicious code; or a small piece of code that opens a system up for exploitation, sometimes by not necessarily involving a command-line shell.|
| **spyware** | Software that gathers information and passes it to a third-party without adequate permission from the owner of the data. It may also refer to software that makes changes to a system or any of its component software, or which makes use of system resources without the full understanding and consent of the system owner.|
| **trackware** | Malware that traces a user's path on the Internet and sends information to third parties. Compare to spyware, which monitors system activity to capture confidential information such as passwords.|
| **trojan** | Malware disguised as something inert or benign.|
| **virus** | Self-replicating malware that requires human interaction to spread; also, self-replicating malware that runs and spreads by modifying and inserting itself into other programs or files.|
| **web-bug** | Code embedded in a web page or email that checks whether a user has accessed the content (e.g., a tiny, transparent GIF image).|
| **worm** | Self-replicating malware that propagates across a network either with or without human interaction.|

## Operating System Features

**Vocabulary Name**: `os-features-ov`

The Operating System Features open vocabulary is used by the following object/property:

* Malware Instance --> *os_features*

This vocabulary is a non-exhaustive enumeration of operating system features that may be used by malware. Each feature is specific to a particular operating system, unless otherwise specified by “multi-OS” in its description, in which case it can apply to a range of operating systems.

| Value | Description |
| ----- | ----------- |
|**login-items** | Indicates use of MacOS/OS X login items.|
|**plist-files** | Indicates use of MacOS/OS X plist files.|
|**applescript** | Indicates use of MacOS/OS X AppleScript.|
|**launch-agent** | Indicates use of a MacOS/OS X launch agent.|
|**launch-daemons** | Indicates use of MacOS/OS X launch daemons.|
|**kext** | Indicates the use of MacOS/OS X kernel extensions (kexts).|
|**login-logout-hooks** | Indicates the use of MacOS/OS X login/logout hooks.|
|**named-pipes** | Indicates use of named pipes (multi-OS).|
|**berkeley-sockets** | Indicates use of Berkeley sockets (multi-OS).|
|**cron** | Indicates use of the Linux or MacOS/OS X cron jobs.|
|**mutexes** | Indicates use of mutual exclusion objects (mutexes) (multi-OS).|
|**registry-keys** | Indicates use of Windows registry keys.|
|**services** | Indicates use of Windows services.|
|**powershell** | Indicates use of Windows powershell.|
|**ntfs-extended-attributes** | Indicates use of Windows NTFS extended attributes.|
|**network-shares** | Indicates use of Windows network shares.|
|**hooks** | Indicates use of Windows hooks.|
|**wmi** | Indicates use of Windows Management Instrumentation (WMI).|
|**task-scheduler** | Indicates use of Windows task scheduler (scheduled tasks).|
|**critical-sections** | Indicates of Windows critical sections.|
|**device-drivers** | Indicates use of device drivers (multi-OS).|
|**admin-network-shares** | Indicates use of Windows administrator (ADMIN$) network shares.|


## Operating Systems

**Vocabulary Name**: `operating-system-ov`

The Operating System open vocabulary is used by the following objects/properties:

* Behavior --> attributes
* Capability --> attributes 

This vocabulary is a non-exhaustive enumeration of operating systems.

| Value | Description |
| ----- | ----------- |
|**android-1.0.x** | Indicates the Android 1.0.x operating system.|
|**android-1.1.x** | Indicates the Android 1.1.x operating system.|
|**android-1.5.x** | Indicates the Android 1.5.x operating system.|
|**android-1.6.x** | Indicates the Android 1.6.x operating system.|
|**android-2.0.x** | Indicates the Android 2.0.x operating system.|
|**android-2.1.x** | Indicates the Android 2.1.x operating system.|
|**android-2.2.x** | Indicates the Android 2.2.x operating system.|
|**android-2.3.x** | Indicates the Android 2.3.x operating system.|
|**android-3.0.x** | Indicates the Android 3.0.x operating system.|
|**android-3.1.x** | Indicates the Android 3.1.x operating system.|
|**android-3.2.x** | Indicates the Android 3.2.x operating system.|
|**android-4.0.x** | Indicates the Android 4.0.x operating system.|
|**android-4.1.x** | Indicates the Android 4.1.x operating system.|
|**android-4.2.x** | Indicates the Android 4.2.x operating system.|
|**android-4.3.x** | Indicates the Android 4.3.x operating system.|
|**android-4.4.x** | Indicates the Android 4.4.x operating system.|
|**android-5.0.x** | Indicates the Android 5.0.x operating system.|
|**android-5.1.x** | Indicates the Android 5.1.x operating system.|
|**android-unknown-version** | Indicates an unknown version of the Android operating system.|
|**ios-1.0.x** | Indicates the iOS 1.0.x operating system.|
|**ios-1.1.x** | Indicates the iOS 1.1.x operating system.|
|**ios-2.0.x** | Indicates the iOS 2.0.x operating system.|
|**ios-2.1.x** | Indicates the iOS 2.1.x operating system.|
|**ios-2.2.x** | Indicates the iOS 2.2.x operating system.|
|**ios-3.0.x** | Indicates the iOS 3.0.x operating system.|
|**ios-3.1.x** | Indicates the iOS 3.1.x operating system.|
|**ios-3.2.x** | Indicates the iOS 3.2.x operating system.|
|**ios-4.0.x** | Indicates the iOS 4.0.x operating system.|
|**ios-4.1.x** | Indicates the iOS 4.1.x operating system.|
|**ios-4.2.x** | Indicates the iOS 4.2.x operating system.|
|**ios-4.3.x** | Indicates the iOS 4.3.x operating system.|
|**ios-5.0.x** | Indicates the iOS 5.0.x operating system.|
|**ios-5.1.x** | Indicates the iOS 5.1.x operating system.|
|**ios-6.0.x** | Indicates the iOS 6.0.x operating system.|
|**ios-6.1.x** | Indicates the iOS 6.1.x operating system.|
|**ios-7.0.x** | Indicates the iOS 7.0.x operating system.|
|**ios-7.1.x** | Indicates the iOS 7.1.x operating system.|
|**ios-8.0.x** | Indicates the iOS 8.0.x operating system.|
|**ios-8.1.x** | Indicates the iOS 8.1.x operating system.|
|**ios-8.2.x** | Indicates the iOS 8.2.x operating system.|
|**ios-8.3.x** | Indicates the iOS 8.3.x operating system.|
|**ios-8.4.x** | Indicates the iOS 8.4.x operating system.|
|**ios-9.0.x** | Indicates the iOS 9.0.x operating system.|
|**ios-9.1.x** | Indicates the iOS 9.1.x operating system.|
|**ios-9.2.x** | Indicates the iOS 9.2.x operating system.|
|**ios-9.3.x** | Indicates the iOS 9.3.x operating system.|
|**ios-10.0.x** | Indicates the iOS 10.0.x operating system.|
|**ios-10.1.x** | Indicates the iOS 10.1.x operating system.|
|**ios-unknown-version** | Indicates an unknown version of the iOS operating system.|
|**linux-kernel-2.4.x** | Indicates version 2.4.x of the linux kernel.
|**linux-kernel-2.6.x** | Indicates version 2.6.x of the linux kernel.
|**linux-kernel-3.0.x** | Indicates version 3.0.x of the linux kernel.
|**linux-kernel-3.1.x** | Indicates version 3.1.x of the linux kernel.
|**linux-kernel-3.2.x** | Indicates version 3.2.x of the linux kernel.
|**linux-kernel-3.3.x** | Indicates version 3.3.x of the linux kernel.
|**linux-kernel-3.4.x** | Indicates version 3.4.x of the linux kernel.
|**linux-kernel-3.5.x** | Indicates version 3.5.x of the linux kernel.
|**linux-kernel-3.6.x** | Indicates version 3.6.x of the linux kernel.
|**linux-kernel-3.7.x** | Indicates version 3.7.x of the linux kernel.
|**linux-kernel-3.8.x** | Indicates version 3.8.x of the linux kernel.
|**linux-kernel-3.9.x** | Indicates version 3.9.x of the linux kernel.
|**linux-kernel-3.10.x** | Indicates version 3.10.x of the linux kernel.
|**linux-kernel-3.11.x** | Indicates version 3.11.x of the linux kernel.
|**linux-kernel-3.12.x** | Indicates version 3.12.x of the linux kernel.
|**linux-kernel-3.13.x** | Indicates version 3.13.x of the linux kernel.
|**linux-kernel-3.14.x** | Indicates version 3.14.x of the linux kernel.
|**linux-kernel-3.15.x** | Indicates version 3.15.x of the linux kernel.
|**linux-kernel-3.16.x** | Indicates version 3.16.x of the linux kernel.
|**linux-kernel-3.17.x** | Indicates version 3.17.x of the linux kernel.
|**linux-kernel-3.18.x** | Indicates version 3.18.x of the linux kernel.
|**linux-kernel-3.19.x** | Indicates version 3.19.x of the linux kernel.
|**linux-kernel-4.0.x** | Indicates version 4.0.x of the linux kernel.
|**linux-kernel-4.1.x** | Indicates version 4.1.x of the linux kernel.
|**linux-unknown-version** | Indicates an unknown version of the linux kernel.
|**mac-os-x-10.0.x** | Indicates the Mac OS X 10.0.x operating system.|
|**mac-os-x-10.1.x** | Indicates the Mac OS X 10.1.x operating system.|
|**mac-os-x-10.2.x** | Indicates the Mac OS X 10.2.x operating system.|
|**mac-os-x-10.3.x** | Indicates the Mac OS X 10.3.x operating system.|
|**mac-os-x-10.4.x** | Indicates the Mac OS X 10.4.x operating system.|
|**mac-os-x-10.5.x** | Indicates the Mac OS X 10.5.x operating system.|
|**mac-os-x-10.6.x** | Indicates the Mac OS X 10.6.x operating system.|
|**mac-os-x-10.7.x** | Indicates the Mac OS X 10.7.x operating system.|
|**mac-os-x-10.8.x** | Indicates the Mac OS X 10.8.x operating system.|
|**mac-os-x-10.9.x** | Indicates the Mac OS X 10.9.x operating system.|
|**mac-os-x-10.10.x** | Indicates the Mac OS X 10.10.x operating system.|
|**mac-os-x-10.11.x** | Indicates the Mac OS X 10.11.x operating system.|
|**mac-os-x-unknown-version** | Indicates an unknown version of the Mac OS X operating system.|
|**windows-7** | Indicates the Windows 7 operating system.|
|**windows-7-sp1** | Indicates the Windows 7 SP1 operating system.|
|**windows-8** | Indicates the Windows 8 operating system.|
|**windows-8.1** | Indicates the Windows 8.1 operating system.|
|**windows-10** | Indicates the Windows 10 operating system.|
|**windows-server-2003** | Indicates the Windows Server 2003 operating system.|
|**windows-server-2003-sp1** | Indicates the Windows Server 2003 SP1 operating system.|
|**windows-server-2003-sp2** | Indicates the Windows Server 2003 SP2 operating system.|
|**windows-server-2008** | Indicates the Windows Server 2008 operating system.|
|**windows-server-2008-sp1** | Indicates the Windows Server 2008 SP1 operating system.|
|**windows-server-2008-sp2** | Indicates the Windows Server 2008 SP2 operating system.|
|**windows-server-2008-r2** | Indicates the Windows Server 2008 r2 operating system.|
|**windows-server-2008-r2-sp1** | Indicates the Windows Server 2008 R2 SP1 operating system.|
|**windows-server-2012** | Indicates the Windows Server 2012 operating system.|
|**windows-server-2012-r2** | Indicates the Windows Server 2012 r2 operating system.|
|**windows-vista** | Indicates the Windows Vista operating system.|
|**windows-vista-sp1** | Indicates the Windows Vista SP1 operating system.|
|**windows-vista-sp2** | Indicates the Windows Vista SP2 operating system.|
|**windows-xp** | Indicates the Windows XP operating system.|
|**windows-xp-sp1** | Indicates the Windows XP SP1 operating system.|
|**windows-xp-sp2** | Indicates the Windows XP SP2 operating system.|
|**windows-xp-sp3** | Indicates the Windows XP SP3 operating system.|
|**windows-unknown-version** | Indicates an unknown version of the Windows operating system.|


## Obfuscation Methods

**Vocabulary Name**: `obfuscation-method-ov`

The Obfuscation Method open vocabulary is used in the following object/property:

* Malware Instance --> static_features --> obfuscation_methods --> *method*

This vocabulary is a non-exhaustive enumeration of obfuscation methods used in obfuscating a binary associated with a Malware Instance.

| Value | Description |
| ----- | ----------- |
|**packing** | Packing of the malware instance code, not including encryption (the code-encryption value defined below should be used for encrypted code).|
|**code-encryption** | Encryption of the malware instance code.|
|**dead-code-insertion** | Dead code inserted in the malware instance.|
|**entry-point-obfuscation** | Obfuscation of the malware instance entry point.|
|**import-address-table-obfuscation** | Obfuscation of the malware instance import address table.|
|**interleaving-code** | Code interleaving in the malware instance (code is split into sections that are rearranged and connected by unconditional jumps).|
|**symbolic-obfuscation** | Obfuscation of the malware instance symbols.|
|**string-obfuscation** | Obfuscation of the malware instance strings.|
|**subroutine-reordering** | Reordering of subroutines in the malware instance.|
|**code-transposition** | Reordering of instructions in the malware instance.|
|**instruction-substitution** | Substitution of malware instance instructions with semantic equivalents.|
|**register-reassignment** | Replacement of unused registers with those containing malicious code.|


## Processor Architectures

**Vocabulary Name**: `processor-architecture-ov`

The Process Architecture open vocabulary is used in the following object/property:

* Malware Instance --> *architecture_execution_envs*

| Value | Description |
| ----- | ----------- |
|**x86** | The 32-bit x86 architecture.|
|**x86-64** | The 64-bit x86 architecture.|
|**ia-64** | The 64-bit IA (Itanium) architecture.|
|**powerpc** | The PowerPC architecture.|
|**arm** | The ARM architecture.|
|**alpha** | The Alpha architecture.|
|**sparc** | The SPARC architecture.|
|**mips** | The MIPS architecture.|


## Refined Capabilities

**Vocabulary Name**: `refined-capability-ov`

The Refined Capability open vocabulary is used in the following object/property:

* Capability --> *name*

| Value | Description |
| ----- | ----------- |
|**access-control-degradation** | Indicates that the malware instance or family is able to bypass or disable access control mechanisms designed to prevent unauthorized or unprivileged use or execution of applications or files.|
|**anti-debugging** | Indicates that the malware instance or family is able to prevent itself from being debugged and/or from being run in a debugger or is able to make debugging more difficult.|
|**anti-disassembly** | Indicates that the malware instance or family is able to prevent itself from being disassembled or make disassembly more difficult.|
|**anti-emulation** | Indicates that the malware instance or family is able to prevent its execution inside of an emulator or is able to make emulation more difficult.|
|**anti-memory-forensics** | Indicates that the malware instance or family is able to prevent or make memory forensics more difficult.|
|**anti-sandbox** | Indicates that the malware instance or family is able to prevent sandbox-based behavioral analysis or make it more difficult.|
|**anti-virus-evasion** | Indicates that the malware instance or family is able to evade detection by anti-virus tools.|
|**anti-vm** | Indicates that the malware instance or family is able to prevent virtual machine (VM) based behavioral analysis or make it more difficult.|
|**authentication-credentials-theft** | Indicates that the malware instance is able to steal authentication credentials.|
|**clean-traces-of-infection** | Indicates that the malware instance or family is able to clean traces of its infection (e.g., file system artifacts) from a system.|
|**communicate-with-c2-server** | Indicates that the malware instance or family is able to communicate (i.e., send or receive data) with a command and control (C2) server.|
|**compromise-data-availability** | Indicates that the malware instance or family is able to compromise the availability of data on the local system on which it is executing and/or one or more remote systems.|
|**compromise-system-availability** | Indicates that the malware instance or family is able to compromise the availability of the local system on which it is executing and/or one or more remote systems.|
|**consume-system-resources** | Indicates that the malware instance or family is able to consume system resources for its own purposes, such as password cracking.|
|**continuous-execution** | Indicates that the malware instance or family is able to continue to execute on a system after significant system events, such as a system reboot.|
|**data-integrity-violation** | Indicates that the malware instance or family is able to compromise the integrity of some data that resides on (e.g., in the case of files) or is received/transmitted (e.g., in the case of network traffic) by the system on which it is executing.|
|**data-obfuscation** | Indicates that the malware instance or family is able to obfuscate data that will be exfiltrated.|
|**data-staging** | Indicates that the malware instance or family is able to gather, prepare, and stage data for exfiltration.|
|**determine-c2-server** | Indicates that the malware instance or family is able to identify one or more command and control (C2) servers with which to communicate.|
|**email-spam** | Indicates that the malware instance or family is able to send spam email messages.|
|**ensure-compatibility** | Indicates that the malware instance or family is able to manipulate or modify the system on which it executes to ensure that it is able to continue executing.|
|**environment-awareness** | Indicates that the malware instance or family can fingerprint or otherwise identify the environment in which it is executing, for the purpose of altering its behavior based on this environment.|
|**file-infection** | Indicates that the malware instance or family is able to infect one or more files on the system on which it executes.|
|**hide-artifacts** | Indicates that the malware instance or family is able to hide its artifacts, such as files and open ports.|
|**hide-executing-code** | Indicates that the malware instance or family is able to hide its executing code.|
|**hide-non-executing-code** | Indicates that the malware instance or family is able to hide its non-executing code.|
|**host-configuration-probing** | Indicates that the malware instance or family is able to probe the configuration of the host system on which it executes.|
|**information-gathering-for-improvement** | Indicates that the malware instance or family is able to gather information from its environment to make itself less likely to be detected.|
|**input-peripheral-capture** | Indicates that the malware instance or family is able to capture data from a system's input peripheral devices, such as a keyboard or mouse.|
|**install-other-components** | Indicates that the malware instance or family is able to install additional components. This encompasses the dropping/downloading of other malicious components such as libraries, other malware, and tools.|
|**local-machine-control** | Indicates that the malware instance or family is able to control the machine on which it is executing.|
|**network-environment-probing** | Indicates that the malware instance or family is able to probe the properties of its network environment, e.g. to determine whether it funnels traffic through a proxy.|
|**os-security-feature-degradation** | Indicates that the malware instance or family is able to bypass or disable operating system (OS) security mechanisms.|
|**output-peripheral-capture** | Indicates that the malware instance or family captures data sent to a system's output peripherals, such as a display.|
|**physical-entity-destruction** | Indicates that the malware instance or family is able to destroy physical entities.|
|**prevent-artifact-access** | Indicates that the malware instance or family is able to prevent its artifacts (e.g., files, registry keys, etc.) from being accessed.|
|**prevent-artifact-deletion** | Indicates that the malware instance or family is able to prevent its artifacts (e.g., files, registry keys, etc.) from being deleted.|
|**remote-machine-access** | Indicates that the malware instance or family is able to access one or more remote machines.|
|**remote-machine-infection** | Indicates that the malware instance or family is able to self-propagate to a remote machine or infect a machine with malware that is different than itself.|
|**security-software-degradation** | Indicates that the malware instance or family is able to bypass or disable security programs running on a system, either by stopping them from executing or by making changes to their code or configuration parameters.|
|**security-software-evasion** | Indicates that the malware instance or family is able to evade security software (e.g., anti-virus tools).|
|**self-modification** | Indicates that the malware instance or family is able to modify itself.|
|**service-provider-security-feature-degradation** | Indicates that the malware instance or family is able to bypass or disable mobile device service provider security features that would otherwise identify or notify users of its presence.|
|**stored-information-theft** | Indicates that the malware instance or family is able to steal information stored on a system (e.g., files).|
|**system-interface-data-capture** | Indicates that the malware instance or family is able to capture data from a system's logical or physical interfaces, such as from a network interface.|
|**system-operational-integrity-violation** | Indicates that the malware instance or family is able to compromise the operational integrity of the system on which it is executing and/or one or more remote systems, e.g., by causing them to operate beyond their set of specified operational parameters.|
|**system-re-infection** | Indicates that the malware instance or family is able to re-infect a system after one or more of its components have been removed.|
|**system-state-data-capture** | Indicates that the malware instance or family is able to capture information about a system's state (e.g., data currently in its RAM).|
|**system-update-degradation** | Indicates that the malware instance or family is able to disable the downloading and installation of system updates and patches.|
|**user-data-theft** | Indicates that the malware instance or family is able to steal data associated with one or more users (e.g., browser history).|
|**virtual-entity-destruction** | Indicates that the malware instance or family is able to destroy a virtual entity.|
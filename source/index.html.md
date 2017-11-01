---
title: MAEC 5 Specification Reference

language_tabs: # must be one of https://git.io/vQNgJ
  - json

toc_footers:
  - <a href='http://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html'>Full Specification</a>
  - <a href='https://cti-tc.github.io'>Documentation</a>

search: true
---

# Introduction

> Start with an example! This is an Malware Instance that was analyzed using a sandbox:

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

Welcome to MAEC 5, a comprehensive language and data model for the exchange of malware data.

This page is just a basic outline of the MAEC 5.0 data model. If you're looking for an introduction or conceptual overview of MAEC, see the [full specification](http://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html). There's also the [documentation website](http://maecproject.github.io/) if you're looking for more examples and information.

This documentation is divided into three major sections&hellip;

**Top-level Objects**

Start here. This is the description for the main top-level objects in MAEC. It includes things like the Malware Instance and Malware Family Objects, the Behavior Object, etc.

**Vocabularies**

Many of the core objects contain properties that let you pick from a list of values. These vocabularies define those lists. In most cases, you don't actually have to use a value from the vocabulary, it's just recommended to improve compatibility.

**Common Types**

These common types are used by the core objects (and sometimes by other common types).

# Top-level Objects

## Behavior

> A Persistence Behavior composed of Several Actions:

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
| **name** (required) | [open-vocab](#open-vocab) | Captures the name of the Behavior. The values for this property **SHOULD** come from the [behavior-ov][#behavior-ov] open vocabulary.|
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

> A basic collection of Malware Instances that were observed together:

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
| **association_type** (optional) | [open-vocab](#open-vocab)| Specifies how the contents of the Collection are associated. The values for this property **SHOULD** come from the [entity-association-ov](#entity-association-ov) vocabulary. |
| **entity_refs** (optional) | [list](#list) of type [identifier](#identifier) |Specifies a set of one or more MAEC entities that are contained in the Collection. Each item specifies the unique ID of the entity being referenced. All entities **MUST** be present in the current Package. This property is mutually exclusive with regard to the **observable_refs** property and both properties **MUST NOT** be present in the same Collection.|
| **observable_refs** (optional) | [list](#list) of type [object-ref](#object-ref) |Specifies a set of one or more STIX Cyber Observable Objects that are contained in the Collection. All Cyber Observable Objects **MUST** be present in the current Package. This property is mutually exclusive with regard to the **entity_refs** property and both properties **MUST NOT** be present in the same Collection.|

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

> A basic Create File Action

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
| **name** (required) | [open-vocab](#open-vocab) | Captures the name of the Malware Action. The values for this property **SHOULD** come from the [malware-action-ov](#malware-action-ov) vocabulary.|
| **description** (optional) | [string](#string) | Captures a basic textual description of the Malware Action. |
| **is_successful** (optional) | [boolean](#boolean) | Specifies whether the Malware Action was successful in its execution. |
| **timestamp** (optional) | [timestamp](#timestamp) | Captures the local or relative time(s) at which the Malware Action occurred or was observed. |
| **input_object_refs** (optional) | [list](#list) of type [object-ref](#object-ref) |References STIX Observable Objects used as input(s) to the Malware Action. The Object(s) referenced **MUST** be specified in the **observable_objects** property of the Package.|
| **output_object_refs** (optional) | [list](#list) of type [object-ref](#object-ref) |References STIX Observable Objects resulting as output(s) from the Malware Action. The Object(s) referenced **MUST** be specified in the **observable_objects** property of the Package.|
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

> A basic Malware Family:

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

> An expanded Malware Family:

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
| **labels** (optional) | [list](#list) of type [open-vocab](#open-vocab) | Specifies one or more commonly accepted labels to describe the members of the Malware Family, e.g. “worm.” The values for this property **SHOULD** come from the [malware-label-ov](#malware-label-ov) vocabulary.|
| **description** (optional) | [string](#string) | Captures a basic, textual description of the Malware Family. |
| **field_data** (required) | [field-data](#field-data) | Specifies field data about the Malware Family, such as first seen and last seen dates, as well as delivery vectors.|
| **common_strings** (optional) | [list](#list) of type [string](#string) | Specifies any strings common to all members of the Malware Family.|
| **common_capabilities** (optional) | [list](#list) of type [object-ref](#object-ref) | Specifies any Capabilities common to all members of the Malware Family.|
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

> Malware Instance with Actions

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
| **labels** (required) | [list](#list) of type [open-vocab](#open-vocab) | Specifies the type of indicator. This is an open vocabulary and values **SHOULD** come from the [indicator-label-ov](#indicator-label) vocabulary.
| **instance_object_refs** (optional) | [list](#list) of type [object-ref](#object-ref) | References the Cyber Observable Objects that characterize the packaged code (typically a binary) associated with the Malware Instance Object. For most use cases, the object referenced **SHOULD** be of STIX Cyber Observable type `file`. Objects referenced **MUST** be specified in the **observable_objects** property of the Package. For cases where multiple STIX Observable File Objects are referenced by this property, each Object **MUST** have the same hash value (via the **hashes** property) but **MAY** have different file names (via the **name** property). |
| **name** (optional) | [name](#name) | Captures the name of the Malware Instance, as specified by the producer of the MAEC Package. |
| **aliases** (optional) | [list](#list) of type [name](#name) | Captures any aliases for the name of the Malware Instance, as reported by sources other than the producer of the MAEC document (e.g., AV vendors). |
| **labels** (optional) | [list](#list) of type [open-vocab](#open-vocab) | Specifies one or more commonly accepted labels to describe the Malware Instance, e.g. “trojan.” The values for this property **SHOULD** come from the [malware-label-ov](#malware-label-ov) vocabulary.|
| **description** (optional) | [string](#string) | Captures a basic, textual description of the Malware Instance. |
| **field_data** (optional) | [field-data](#field-data) | Specifies field data about the Malware Instance, such as first seen and last seen dates, as well as delivery vectors.|
| **os_execution_envs** (optional) | [list](#list) of type [open-vocab](#open-vocab) | Specifies the operating systems that the Malware Instance executes on. The values for this property **SHOULD** come from the [operating-system-ov](#operating-system-ov) vocabulary. |
| **architecture_execution_envs** (optional) | [list](#list) of type [open-vocab](#open-vocab) | Specifies the processor architectures that the Malware Instance executes on. The values for this property **SHOULD** come from the [processor-architecture-ov](#processor-architecture-ov) vocabulary. |
| **capabilities** (optional) | [list](#list) of type [capability](#capability) | Specifies a set of one or more Capabilities possessed by the Malware Instance. |
| **os_features** (optional) | [list](#list) of type [open-vocab](#open-vocab) | Specifies any operating system-specific features used by the Malware Instance. Each item in the list specifies a single feature. The values for this property **SHOULD** come from the [os-features-ov](#os-features-ov) vocabulary. |
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

## API call
**Type Name**: `api-call`

The api-call type serves as a method for characterizing API Calls, as implementations of Malware Actions.

Name | Type | Description
--------- | ------- | -----------
| **address** (optional) | [hex](#hex) | Captures the hexadecimal address of the API call in the binary.|
| **return_value** (optional) | [string](#string) | Captures the return value of the API call.|

# Vocabularies

## Attack Motivation

**Vocabulary Name**: `attack-motivation-ov`

The attack motivation vocabulary is currently used in the following SDOs:

* Intrusion Set
* Threat Actor

Knowing a Threat Actor or Intrusion Set's motivation may allow an analyst or defender to better understand likely targets and behaviors.

Motivation shapes the intensity and the persistence of an attack. Threat Actors and Intrusion Sets usually act in a manner that reflects their underlying emotion or situation, and this informs defenders of the manner of attack. For example, a spy motivated by nationalism (ideology) likely has the patience to achieve long-term goals and work quietly for years, whereas a cyber-vandal out for notoriety can create an intense and attention-grabbing attack but may quickly lose interest and move on. Understanding these differences allows defenders to implement controls tailored to each type of attack for greatest efficiency.

This section including vocabulary items and their descriptions is based on the Threat Agent Motivations publication from Intel Corp in February 2015 [Casey 2015].

| Value | Description |
| ----- | ----------- |
| **accidental** | A non-hostile actor whose benevolent or harmless intent inadvertently causes harm. For example, a well-meaning and dedicated employee who through distraction or poor training unintentionally causes harm to his or her organization.
| **coercion** | Being forced to act on someone else's behalf. Adversaries who are motivated by coercion are often forced through intimidation or blackmail to act illegally for someone else’s benefit. Unlike the other motivations, a coerced person does not act for personal gain, but out of fear of incurring a loss.
| **dominance** | A desire to assert superiority over someone or something else. Adversaries who are seeking dominance over a target are focused on using their power to force their target into submission or irrelevance. Dominance may be found with ideology in some state-sponsored attacks and with notoriety in some cyber vandalism based attacks.
| **ideology** | A passion to express a set of ideas, beliefs, and values that may shape and drive harmful and illegal acts. Adversaries who act for ideological reasons (e.g., political, religious, human rights, environmental, desire to cause chaos/anarchy, etc.) are not usually motivated primarily by the desire for profit; they are acting on their own sense of morality, justice, or political loyalty. For example, an activist group may sabotage a company’s equipment because they believe the company is harming the environment.
| **notoriety** | Seeking prestige or to become well known through some activity. Adversaries motivated by notoriety are often seeking either personal validation or respect within a community and staying covert is not a priority. In fact one of the main goals is to garner the respect of their target audience.
| **organizational-gain** | Seeking advantage over a competing organization, including a military organization. Adversaries motivated by increased profit or other gains through an unfairly obtained competitive advantage are often seeking theft of intellectual property, business processes, or supply chain agreements and thus accelerating their position in a market or capability.
| **personal-gain** | The desire to improve one’s own financial status. Adversaries motivated by a selfish desire for personal gain are often out for gains that come from financial fraud, hacking for hire, or intellectual property theft. While a Threat Actor or Intrusion Set may be seeking personal gain this does not mean they are acting alone. Individuals can band together solely to maximize their own personal profits.
| **personal-satisfaction** | A desire to satisfy a strictly personal goal, including curiosity, thrill-seeking, amusement, etc. Threat Actors or Intrusion Set driven by personal satisfaction may incidentally receive some other gain from their actions, such as a profit, but their primary motivation is to gratify a personal, emotional need. Individuals can band together with others toward a mutual, but not necessarily organizational, objective.
| **revenge** | A desire to avenge perceived wrongs through harmful actions such as sabotage, violence, theft, fraud, or embarrassing certain individuals or the organization. A disgruntled Threat Actor or Intrusion Set seeking revenge can include current or former employees, who may have extensive knowledge to leverage when conducting attacks. Individuals can band together with others if the individual believes that doing so will enable them to cause more harm.
| **unpredictable** | Acting without identifiable reason or purpose and creating unpredictable events. Unpredictable is not a miscellaneous or default category. Unpredictable means a truly random and likely bizarre event, which seems to have no logical purpose to the victims.

## Attack Resource Level

**Vocabulary Name**: `attack-resource-level-ov`

The attack resource level vocabulary is currently used in the following SDO(s):

* Intrusion Set
* Threat Actor

Attack Resource Level is an open vocabulary that captures the general level of resources that a threat actor, intrusion set, or campaign might have access to. It ranges from individual, a person acting alone, to government, the resources of a national government.

This section including vocabulary items and their descriptions is based on the Threat Agent Library publication from Intel Corp in September 2007 [Casey 2007].

| Value | Description |
| ----- | ----------- |
| **individual** | Resources limited to the average individual; Threat Actor acts independently.
| **club** | Members interact on a social and volunteer basis, often with little personal interest in the specific target. An example might be a core group of unrelated activists who regularly exchange tips on a particular blog. Group persists long term.
| **contest** | A short-lived and perhaps anonymous interaction that concludes when the participants have achieved a single goal. For example, people who break into systems just for thrills or prestige may hold a contest to see who can break into a specific target first. It also includes announced "operations" to achieve a specific goal, such as the original "OpIsrael" call for volunteers to disrupt all of Israel's Internet functions for a day.
| **team** | A formally organized group with a leader, typically motivated by a specific goal and organized around that goal. Group persists long term and typically operates within a single geography.
| **organization** | Larger and better resourced than a team; typically a company or crime syndicate. Usually operates in multiple geographic areas and persists long term.
| **government** | Controls public assets and functions within a jurisdiction; very well resourced and persists long term.

## Hash Algorithm

**Vocabulary Name**: `hash-algorithm-ov`

An open vocabulary of hashing algorithms.

When specifying a hashing algorithm not already defined within the hash-algorithm-ov, wherever an authoritative name for a hashing algorithm name is defined, it should be used as the value. In cases where no authoritative name exists and/or where there is variance in the naming of a particular hashing algorithm, producers should exercise their best judgement.

| Value | Description |
| ----- | ----------- |
| **MD5** | Specifies the MD5 message digest algorithm. The corresponding hash string for this value **MUST** be a valid MD5 message digest as defined in [RFC 1321].
| **MD6** | Specifies the MD6 message digest algorithm. The corresponding hash string for this value **MUST** be a valid MD6 message digest as defined in the [MD6] proposal.
| **RIPEMD-160** | Specifies the RIPEMD­-160 (R​ACE​ Integrity Primitives Evaluation Message Digest)​ cryptographic hash function. The corresponding hash string for this value **MUST** be a valid RIPEMD-160 message digest as defined in the [RIPEMD-160] specification.
| **SHA-1** | Specifies the SHA­-1 (secure-­hash algorithm 1) cryptographic hash function. The corresponding hash string for this value **MUST** be a valid SHA-1 message digest as defined in [RFC 3174].
| **SHA-224** | Specifies the SHA-­224 cryptographic hash function (part of the SHA­2 family). The corresponding hash string for this value **MUST** be a valid SHA-224 message digest as defined in [RFC 6234].
| **SHA-256** | Specifies the SHA-­256 cryptographic hash function (part of the SHA­2 family). The corresponding hash string for this value **MUST** be a valid SHA-256 message digest as defined in [RFC 6234].
| **SHA-384** | Specifies the SHA-­384 cryptographic hash function (part of the SHA­2 family). The corresponding hash string for this value **MUST** be a valid SHA-384 message digest as defined in [RFC 6234].
| **SHA-512** | Specifies the SHA-­512 cryptographic hash function (part of the SHA­2 family). The corresponding hash string for this value **MUST** be a valid SHA-512 message digest as defined in [RFC 6234].
| **SHA3-224** | Specifies the SHA3-224 cryptographic hash function. The corresponding hash string for this value **MUST** be a valid SHA3-224 message digest as defined in [FIPS202].
| **SHA3-256** | Specifies the SHA3-256 cryptographic hash function. The corresponding hash string for this value **MUST** be a valid SHA3-256 message digest as defined in [FIPS202].
| **SHA3-384** | Specifies the SHA3-384 cryptographic hash function. The corresponding hash string for this value **MUST** be a valid SHA3-384 message digest as defined in [FIPS202].
| **SHA3-512** | Specifies the SHA3-512 cryptographic hash function. The corresponding hash string for this value **MUST** be a valid SHA3-512 message digest as defined in [FIPS202].
| **ssdeep** | Specifies the ssdeep fuzzy hashing algorithm. The corresponding hash string for this value **MUST** be a valid piecewise hash as defined in the [SSDEEP] specification.
| **WHIRLPOOL** | Specifies the whirlpool cryptographic hash function. The corresponding hash string for this value **MUST** be a valid WHIRLPOOL message digest as defined in [ISO10118].

## Identity Class

**Vocabulary Name**: `identity-class-ov`

The identity class vocabulary is currently used in the following SDO(s):
Identity

This vocabulary describes the type of entity that the Identity represents: whether it describes an organization, group, individual, or class.

| Value | Description |
| ----- | ----------- |
| **individual** | A single person.|
| **group** | An informal collection of people, without formal governance, such as a distributed hacker group.|
| **organization** | A formal organization of people, with governance, such as a company or country.|
| **class** | A class of entities, such as all hospitals, all Europeans, or the Domain Administrators in a system.|
| **unknown** | It is unknown whether the classification is individual, group, organization, or class.|

## Indicator Label

**Vocabulary Name**: `indicator-label-ov`

The indicator label vocabulary is currently used in the following SDO(s):

* Indicator

Indicator labels is an open vocabulary used to categorize Indicators. It is intended to be high-level to promote consistent practices.

Indicator labels should not be used to capture information that can be better captured via related Malware or Attack Pattern objects. It is better to link an Indicator to a Malware object describing Poison Ivy rather than simply labeling it with "poison-ivy".

| Value | Description |
| ----- | ----------- |
**anomalous-activity** | Unexpected, or unusual activity that may not necessarily be malicious or indicate compromise. This type of activity may include reconnaissance-like behavior such as port scans or version identification, network behavior anomalies, and asset and/or user behavioral anomalies.
| **anonymization** | Suspected anonymization tools or infrastructure (proxy, TOR, VPN, etc.).
| **benign** | Activity that is not suspicious or malicious in and of itself, but when combined with other activity may indicate suspicious or malicious behavior.
| **compromised** | Assets that are suspected to be compromised.
| **malicious-activity** | Patterns of suspected malicious objects and/or activity.
| **attribution** |Patterns of behavior that indicate attribution to a particular Threat Actor or Campaign.

## Industry Sector

**Vocabulary Name**: `industry-sector-ov`

The industry sector vocabulary is currently used in the following SDO(s):

* Identity

Industry sector is an open vocabulary that describes industrial and commercial sectors. It is intended to be holistic; it has been derived from several other lists and is not limited to "critical infrastructure" sectors.

| Value | Description |
| ----- | ----------- |
**agriculture**|
**aerospace**|
**automotive**|
**communications**|
**construction**|
**defence**|
**education**|
**energy**|
**entertainment**|
**financial-services**|
**government-national**|
**government-regional**|
**government-local**|
**government-public-services**|emergency services, sanitation
**healthcare**|
**hospitality-leisure**|
**infrastructure**|
**insurance**|
**manufacturing**|
**mining**|
**non-profit**|
**pharmaceuticals**|
**retail**|
**technology**|
**telecommunications**|
**transportation**|
**utilities**|

## Malware Label

**Vocabulary Name**: `malware-label-ov`

The malware label vocabulary is currently used in the following SDO(s):

* Malware

Malware label is an open vocabulary that represents different types and functions of malware. Malware labels are not mutually exclusive; a malware instance can be both spyware and a screen capture tool.

| Value | Description |
| ----- | ----------- |
**adware**|Any software that is funded by advertising. Adware may also gather sensitive user information from a system.
**backdoor**|A malicious program that allows an attacker to perform actions on a remote system, such as transferring files, acquiring passwords, or executing arbitrary commands [Mell2005].
**bot**|A program that resides on an infected system, communicating with and forming part of a botnet. The bot may be implanted by a worm or Trojan, which opens a backdoor. The bot then monitors the backdoor for further instructions.
**ddos**|A tool used to perform a distributed denial of service attack.
**dropper**|A type of trojan that deposits an enclosed payload (generally, other malware) onto the target computer.
**exploit-kit**|A software toolkit to target common vulnerabilities.
**keylogger**|A type of malware that surreptitiously monitors keystrokes and either records them for later retrieval or sends them back to a central collection point.
**ransomware**|A type of malware that encrypts files on a victim's system, demanding payment of ransom in return for the access codes required to unlock files.
**remote-access-trojan**|A remote access trojan program (or RAT), is a trojan horse capable of controlling a machine through commands issued by a remote attacker.
**resource-exploitation**|A type of malware that steals a system's resources (e.g., CPU cycles), such as a bitcoin miner.
**rogue-security-software**|A fake security product that demands money to clean phony infections.
**rootkit**|A type of malware that hides its files or processes from normal methods of monitoring in order to conceal its presence and activities. Rootkits can operate at a number of levels, from the application level — simply replacing or adjusting the settings of system software to prevent the display of certain information — through hooking certain functions or inserting modules or drivers into the operating system kernel, to the deeper level of firmware or virtualization rootkits, which are activated before the operating system and thus even harder to detect while the system is running.
**screen-capture**|A type of malware used to capture images from the target systems screen, used for exfiltration and command and control.
**spyware**|Software that gathers information on a user's system without their knowledge and sends it to another party. Spyware is generally used to track activities for the purpose of delivering advertising.
**trojan**|Any malicious computer program which is used to hack into a computer by misleading users of its true intent.
**virus**|A malicious computer program that replicates by reproducing itself or infecting other programs by modifying them.
**worm**|A self-replicating, self-contained program that usually executes itself without user intervention.

## Report Label

**Vocabulary Name**: `report-label-ov`

The report label vocabulary is currently used in the following SDO(s):

* Report

Report label is an open vocabulary to describe the primary purpose or subject of a report. For example, a report that contains malware and indicators for that malware should have a report label of malware to capture that the malware is the primary purpose. Report labels are not mutually exclusive: a Report can be both a malware report and a tool report. Just because a report contains objects of a type does not mean that the report should include that label.  If the objects are there to simply provide evidence or context for other objects, it is not necessary to include them in the label.

| Value | Description |
| ----- | ----------- |
**threat-report**|Report subject is a broad characterization of a threat across multiple facets.
**attack-pattern**|Report subject is a characterization of one or more attack patterns and related information.
**campaign**|Report subject is a characterization of one or more campaigns and related information.
**identity**|Report subject is a characterization of one or more identities and related information.
**indicator**|Report subject is a characterization of one or more indicators and related information.
**intrusion-set**|Report subject is a characterization of one or more intrusion sets and related information.
**malware**|Report subject is a characterization of one or more malware instances and related information.
**observed-data**|Report subject is a characterization of observed data and related information.
**threat-actor**|Report subject is a characterization of one or more threat actors and related information.
**tool**|Report subject is a characterization of one or more tools and related information.
**vulnerability**|Report subject is a characterization of one or more vulnerabilities and related information.

## Threat Actor Label

**Vocabulary Name**: `threat-actor-label-ov`

The threat actor label vocabulary is currently used in the following SDO(s):

* Threat Actor

Threat actor label is an open vocabulary used to describe what type of threat actor the individual or group is. For example, some threat actors are competitors who try to steal information, while others are activists who act in support of a social or political cause. Actor labels are not mutually exclusive: a threat actor can be both a disgruntled insider and a spy. [Casey 2007])

| Value | Description |
| ----- | ----------- |
| **activist** | Highly motivated, potentially destructive supporter of a social or political cause (e.g., trade, labor, environment, etc.) that attempts to disrupt an organization's business model or damage their image. This category includes actors sometimes referred to as anarchists, cyber vandals, extremists, and hacktivists.
| **competitor** | An organization that competes in the same economic marketplace. The goal of a competitor is to gain an advantage in business with respect to the rival organization it targets. It usually does this by copying intellectual property, trade secrets, acquisition strategies, or other technical or business data from a rival organization with the intention of using the data to bolster its own assets and market position.  
| **crime-syndicate** | An enterprise organized to conduct significant, large-scale criminal activity for profit. Crime syndicates, also known as organized crime, are generally large, well-resourced groups that operate to create profit from all types of crime.
| **criminal** | Individual who commits computer crimes, often for personal financial gain and often involves the theft of something valuable. Intellectual property theft, extortion via ransomware, and physical destruction are common examples. A criminal as defined here refers to those acting individually or in very small or informal groups. For sophisticated organized criminal activity, see the crime syndicate descriptor.
| **hacker** | An individual that tends to break into networks for the thrill or the challenge of doing so.

## Threat Actor Role

**Vocabulary Name**: `threat-actor-role-ov`

The threat actor role vocabulary is currently used in the following SDO(s):

* Threat Actor

Threat actor role is an open vocabulary that is used to describe the different roles that a threat actor can play. For example, some threat actors author malware or operate botnets while other actors actually carry out attacks directly.

Threat actor roles are not mutually exclusive. For example, an actor can be both a financial backer for attacks and also direct attacks.

| Value | Description |
| ----- | ----------- |
| **agent** |Threat actor executes attacks either on behalf of themselves or at the direction of someone else.
| **director** |The threat actor who directs the activities, goals, and objectives of the malicious activities.
| **independent** |A threat actor acting by themselves.
| **infrastructure-architect** |Someone who designs the battle space.
| **infrastructure-operator** |The threat actor who provides and supports the attack infrastructure that is used to deliver the attack (botnet providers, cloud services, etc.).
| **malware-author** |The threat actor who authors malware or other malicious tools.
| **sponsor** |The threat actor who funds the malicious activities.

## Threat Actor Sophistication

**Vocabulary Name**: `threat-actor-sophistication-ov`

Threat actor sophistication vocabulary is currently used in the following SDO(s):

* Threat Actor

Threat actor sophistication vocabulary captures the skill level of a threat actor. It ranges from "none", which describes a complete novice, to "strategic", which describes an attacker who is able to influence supply chains to introduce vulnerabilities. This vocabulary is separate from resource level because an innovative, highly-skilled threat actor may have access to very few resources while a minimal-level actor might have the resources of an organized crime ring.

| Value | Description |
| ----- | ----------- |
| **none** | Can carry out random acts of disruption or destruction by running tools they do not understand. Actors in this category have average computer skills.
| **minimal** | Can minimally use existing and frequently well known and easy-to-find techniques and programs or scripts to search for and exploit weaknesses in other computers. Commonly referred to as a script-kiddie.
| **intermediate** | Can proficiently use existing attack frameworks and toolkits to search for and exploit vulnerabilities in computers or systems. Actors in this category have computer skills equivalent to an IT professional and typically have a working knowledge of networks, operating systems, and possibly even defensive techniques and will typically exhibit some operational security.
| **advanced** | Can develop their own tools or scripts from publicly known vulnerabilities to target systems and users. Actors in this category are very adept at IT systems and have a background in software development along with a solid understanding of defensive techniques and operational security.
| **expert** | Can focus on the discovery and use of unknown malicious code, are is adept at installing user and kernel mode rootkits, frequently use data mining tools, target corporate executives and key users (government and industry) for the purpose of stealing personal and corporate data. Actors in this category are very adept at IT systems and software development and are experts with security systems, defensive techniques, attack methods, and operational security.
| **innovator** | Typically criminal or state actors who are organized, highly technical, proficient, well-funded professionals working in teams to discover new vulnerabilities and develop exploits.
| **strategic** | State actors who create vulnerabilities through an active program to “influence” commercial products and services during design, development or manufacturing, or with the ability to impact products while in the supply chain to enable exploitation of networks and systems of interest.

## Tool Label

**Vocabulary Name**: `tool-label-ov`

The tool label vocabulary is currently used in the following SDO(s):

* Tool

Tool labels describe the categories of tools that can be used to perform attacks.

| Value | Description |
| ----- | ----------- |
**denial-of-service**|Tools used to perform denial of service attacks or DDoS attacks, such as Low Orbit Ion Cannon (LOIC) and DHCPig.
**exploitation**|Tools used to exploit software and systems, such as sqlmap and Metasploit.
**information-gathering**|Tools used to enumerate system and network information, e.g., NMAP.
**network-capture**|Tools used to capture network traffic, such as Wireshark and Kismet.
**credential-exploitation**|Tools used to crack password databases or otherwise exploit/discover credentials, either locally or remotely, such as John the Ripper and NCrack.
**remote-access**|Tools used to access machines remotely, such as VNC and Remote Desktop.
**vulnerability-scanning**|Tools used to scan systems and networks for vulnerabilities, e.g., Nessus.

# Common Types

## Boolean

A boolean is a value of either true or false. Properties with this type **MUST** have a value of `true` or `false`.

The JSON MTI serialization uses the JSON boolean type, which is a literal (unquoted) true or false.

## External Reference

> An external-reference to a VERIS Community Database (VCDB) [VERIS] entry:

```json
{
  ...
  "external_references": [
    {
      "source_name": "veris",
      "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
      "url": "https://github.com/vz-risk/VCDB/blob/master/data/json/0001AA7F-C601-424A-B2B8-
             BE6C9F5164E7.json",
      "hashes": {
        "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"
      }
    }
  ],
  ...
}
```

> An external-reference from the CAPEC™ [CAPEC] repository:

```json
{
  ...
  "external_references": [
    {
      "source_name": "capec",
      "external_id": "CAPEC-550",
      "url": "http://capec.mitre.org/data/definitions/550.html"
    }
  ],
  ...
}
```

> An external-reference to ACME Threat Intel's report document:

```json
{
  ...
  "external_references": [
    {
      "source_name": "ACME Threat Intel",
      "description": "Threat report",
      "url": "http://www.example.com/threat-report.pdf"
    }
  ],
  ...
}
```

External references are used to describe pointers to information represented outside of STIX. For example, a Malware object could use an external reference to indicate an ID for that malware in an external database or a report could use references to represent source material.

The JSON MTI serialization uses the JSON object type when representing external-reference.

* In addition to the **source_name** property, at least one of the **description**, **url**, or **external_id** properties **MUST** be present.

Name | Type | Description
--------- | ------- | -----------
| **source_name** (required) | [string](#string) | The source within which the `external-reference` is defined (system, registry, organization, etc.).
| **description** (optional) | [string](#string) | A human readable description.
| **url** (optional) | [string](#string) | A URL reference to an external resource.
| **hashes** (optional) | [hashes](#hashes) | Specifies a dictionary of hashes for the contents of the url. This **SHOULD** be provided when the url property is present.
| **external_id** (optional) | [string](#string) | An identifier for the external reference content.

## Float

The float data type represents an IEEE 754 double-precision number (e.g., a number with a fractional part). However, because the values ±Infinity and NaN are not representable in JSON, they are not valid values in STIX.

In the JSON MTI serialization, floating point values are represented by the JSON number type.

## Hashes

> A SHA-256 hash with a custom hash"

```json
{
  "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
  "x_foo_hash": "aaaabbbbccccddddeeeeffff0123457890"
}
```

The Hashes type represents 1 or more cryptographic hashes, as a special set of key/value pairs. Accordingly, the name of each hashing algorithm **MUST** be specified as a key in the dictionary and **MUST** identify the name of the hashing algorithm used to generate the corresponding value. This name **SHOULD** either be one of the values defined in the [hash-algorithm-ov](#hash-algorithm) OR a custom value prepended with “x_” (e.g., “x_custom_hash”).

Keys **MUST** be unique in each hashes property, **MUST** be in ASCII, and are limited to the characters a-z (lowercase ASCII), A-Z (uppercase ASCII), numerals 0-9, hyphen (`-`), and underscore (`_`). Keys **SHOULD** be no longer than 30 ASCII characters in length, **MUST** have a minimum length of 3 ASCII characters, **MUST** be no longer than 256 ASCII characters in length.

## Identifier

> Example of an identifier for an indicator

```json
{
  ...
  "type": "indicator",
  "id": "indicator--e2e1a340-4415-4ba8-9671-f7343fbf0836",
  ...
}
```

> Example of an identifier for a threat-actor

```json
{
  ...
  "type": "threat-actor",
  "id": "threat-actor--5ee9db36-4a1e-4dd4-bb32-2551eda97f4a",
  ...
}
```

An identifier universally and uniquely identifies a SDO, SRO, Bundle, or Marking Definition. Identifiers **MUST** follow the form `object-type--UUIDv4`, where `object-type` is the exact value (all type names are lowercase strings, by definition) from the `type` property of the object being identified or referenced and where the UUIDv4 is an RFC 4122-compliant Version 4 UUID. The UUID **MUST** be generated according to the algorithm(s) defined in RFC 4122, section 4.4 (Version 4 UUID).

The JSON MTI serialization uses the JSON string type when representing identifier.

## Integer

> Example:

```json
{
  ...
  "count": 8,
  ...
}
```

The integer data type represents a whole number. Unless otherwise specified, all integers **MUST** be capable of being represented as a signed 64-bit value ([-(2**63)+1, (2**63)-1]). Additional restrictions **MAY** be placed on the type as described where it is used.

In the JSON MTI serialization, integers are represented by the JSON number type.

## Kill Chain Phase

> The “reconnaissance” phase from the Lockheed Martin Cyber Kill Chain:

```json
{
  ...
  "kill_chain_phases": [
    {
      "kill_chain_name": "lockheed-martin-cyber-kill-chain",
      "phase_name": "reconnaissance"
    }
  ],
  ...
}
```

> Example specifying the “pre-attack” phase from the “foo” kill-chain

```json
{
  ...
  "kill_chain_phases": [
    {
      "kill_chain_name": "foo",
      "phase_name": "pre-attack"
    }
  ],
  ...
}
```

The `kill-chain-phase` represents a phase in a kill chain, which describes the various phases an attacker may undertake in order to achieve their objectives.

The JSON MTI serialization uses the JSON object type when representing `kill-chain-phase`.

Name | Type | Description
--------- | ------- | -----------
| **kill_chain_name** (required) | [string](#string) | The name of the kill chain. The value of this property **SHOULD** be all lowercase (where lowercase is defined by the locality conventions) and **SHOULD** use hyphens instead of spaces or underscores as word separators.
| **phase_name** (required) | [string](#string) | The name of the phase in the kill chain. The value of this property **SHOULD** be all lowercase (where lowercase is defined by the locality conventions) and **SHOULD** use hyphens instead of spaces or underscores as word separators.

## List

> Example list:

```json
{
  ...
  "observed_data_refs": [
    "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "observed-data--c96f4120-2b4b-47c3-b61f-eceaa54bd9c6",
    "observed-data--787710c9-1988-4a1b-9761-a2de5e19c62f"
  ],
  ...
}
```

The list type defines a sequence of values ordered based on how they appear in the list. The phrasing “list of type \<type\>” is used to indicate that all values within the list **MUST** conform to the specified type. For instance, list of type integer means that all values of the list must be of the integer type. This specification does not specify the maximum number of allowed values in a list, however every instance of a list **MUST** have at least one value. Specific STIX object properties may define more restrictive upper and/or lower bounds for the length of the list.

Empty lists are prohibited in STIX and **MUST NOT** be used as a substitute for omitting the property if it is optional. If the property is required, the list **MUST** be present and **MUST** have at least one value.

The JSON MTI serialization uses the JSON array type, which is an ordered list of zero or more values.

## Open Vocab

> Example using value from the suggested vocabulary:

```json
{
  ...,
  "labels": ["malicious-activity"],
  ...
}
```

> Example of a custom value:

```json
{
  ...,
  "labels": ["pbx-fraud-activity"],
  ...
}
```

The `open-vocab` type is represented as a string. For properties that use this type there will be a list of suggested values, known as the suggested vocabulary, that is identified in the definition for that property. The suggested vocabularies are defined in section 6. The value of the property **SHOULD** be chosen from the suggested vocabulary but **MAY** be any other string value. Values that are not from the suggested vocabulary **SHOULD** be all lowercase (where lowercase is defined by the locality conventions) and **SHOULD** use hyphens instead of spaces or underscores as word separators.

A consumer that receives STIX content with one or more `open-vocab` terms not defined in the suggested vocabulary **MAY** ignore those values.

The JSON MTI serialization uses the JSON string type when representing `open-vocab`.

## String

> Example:

```json
{
  ...
  "name": "The Black Vine Cyberespionage Group",
  ...
}
```

The string data type represents a finite-length string of valid characters from the Unicode coded character set. Unicode incorporates ASCII and the characters of many other international character sets.

The JSON MTI serialization uses the JSON string type, which mandates the UTF-8 encoding for supporting Unicode.

## Timestamp

> Example:

```json
{
  ...
  "created": "2016-01-20T12:31:12.123Z",
  ...
}
```

The timestamp type defines how dates and times are represented in STIX.

The JSON MTI serialization uses the JSON string type when representing timestamp.

* The timestamp property **MUST** be a valid RFC 3339-formatted timestamp using the format YYYY-MM-DDTHH:mm:ss[.s+]Z where the “s+” represents 1 or more sub-second values. The brackets denote that sub-second precision is optional, and that if no digits are provided, the decimal place **MUST NOT** be present.
* The timestamp **MUST** be represented in the UTC timezone and **MUST** use the “Z” designation to indicate this.

## Common Properties

This section outlines the common properties and behavior across all SDOs and SROs. All objects, other than `bundle` and `data-marking`, have all of these properties.

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The **type** property identifies the type of STIX Object. The value of the type property **MUST** be the name of one of the types of STIX Object defined in sections 2 and 3 of STIX™ Version 2.0. Part 2: STIX Objects (e.g., indicator) or the name of a custom object as defined by section 7.2. |
| **id** (required) | [identifier](#identifier) | The **id** property universally and uniquely identifies this object. All objects with the same id are considered different versions of the same object. Because the object type is part of the identifier, it is invalid for objects of different types to share the same id. |
| **created_by_ref** (optional) | [identifier](#identifier) | The **created_by_ref** property specifies the ID of the Identity object that describes the entity that created this object. If this attribute is omitted, the source of this information is undefined. This may be used by object creators who wish to remain anonymous.
| **created** (required) | [timestamp](#timestamp) | The **created** property represents the time at which the first version of this object was created. The object creator can use the time it deems most appropriate as the time the object was created. The **created** property **MUST NOT** be changed when creating a new version of the object. The created timestamp **MUST** be precise to the nearest millisecond (exactly three digits after the decimal place in seconds). See section 3.4 for further definition of versioning.
| **modified** (required) | [timestamp](#timestamp) | The **modified** property represents the time that this particular version of the object was created. The object creator can use the time it deems most appropriate as the time this version of the object was modified. The value of the modified property for a given object version **MUST** be later than or equal to the value of the created property. Object creators **MUST** set the modified property when creating a new version of an object. The modified timestamp **MUST** be precise to the nearest millisecond (exactly three digits after the decimal place in seconds). See section 3.4 for further definition of versioning.
| **revoked** (optional) | [boolean](#boolean) | The **revoked** property indicates whether the object has been revoked. Revoked objects are no longer considered valid by the object creator. Revoking an object is permanent; future versions of the object with this id **MUST NOT** be created. The default value of this property is `false`. See section 3.4 for further definition of versioning.
| **labels** (optional) | [list](#list) of type [string](#string) | The **labels** property specifies a set of classifications. Each STIX Object can define a suggested vocabulary for the labels property. For example, the Indicator object, as defined in section 2.5 of STIX™ Version 2.0. Part 2: STIX Objects, uses the Indicator Label vocabulary as defined in section 6.5. In some cases (generally, when a suggested vocabulary is defined) the labels property is then required for that specific SDO. If a vocabulary is defined, items in this list **SHOULD** come from the vocabulary. Additional labels **MAY** be added beyond what is in the suggested vocabulary.
| **external_references** (optional)  | [list](#list) of type [external-reference](#external-reference) | The **external_references** property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems.
| **object_marking_refs** (optional) | [list](#list) of type [identifier](#identifier) | The **object_marking_refs** property specifies a list of IDs of `marking-definition` objects that apply to this object. See section 4 for further definition of data markings. |
| **granular_markings** (optional) | [list](#list) of type [granular-marking]($granular-marking) | The **granular_markings** property specifies a list of granular markings applied to this object.  See section 4 for further definition of data markings.

## Common Relationships

This section outlines the relationships that are available on all SROs.

Source | Name | Target | Description
------ | ---- | ------ | -----------
| `<SDO>` | `derived-from` | `<SDO of the same type>` | The information in the target object is based on information from the source object. derived-from is an explicit relationship between two separate objects and **MUST NOT** be used as a substitute for the versioning process defined in section 3.4.
| `<SDO>` | `duplicate-of` | `<SDO of the same type>` | The referenced source and target objects are semantically duplicates of each other. This specification does not address whether the source or the target object is the duplicate object or what action, if any, a consumer should take when receiving an instance of this relationship. As an example, a Campaign object from one organization could be marked as a `duplicate-of` a Campaign object from another organization if they both described the same campaign.
| `<SDO>` | `related-to` | `<SDO of any type>` | Asserts a non-specific relationship between two SDOs. This relationship can be used when none of the other predefined relationships are appropriate. As an example, a Malware object describing a piece of malware could be marked as a `related-to` a Tool if they are commonly used together. That relationship is not common enough to standardize on, but may be useful to some analysts.

---
title: STIX 2 Specification Reference

language_tabs: # must be one of https://git.io/vQNgJ
  - json

toc_footers:
  - <a href='http://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html'>Full Specification</a>
  - <a href='https://cti-tc.github.io'>Documentation</a>

search: true
---

# Introduction

> Start with an example! This is an indicator to detect a malware instance:

```json
{
  "type": "bundle",
  "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
      "created": "2016-04-06T20:03:48.000Z",
      "modified": "2016-04-06T20:03:48.000Z",
      "labels": ["malicious-activity"],
      "name": "Poison Ivy Malware",
      "description": "This file is part of Poison Ivy",
      "pattern": "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
      "valid_from": "2016-01-01T00:00:00Z"
    },
    {
      "type": "relationship",
      "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
      "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
      "created": "2016-04-06T20:06:37.000Z",
      "modified": "2016-04-06T20:06:37.000Z",
      "relationship_type": "indicates",
      "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
    },
    {
      "type": "malware",
      "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
      "created": "2016-04-06T20:07:09.000Z",
      "modified": "2016-04-06T20:07:09.000Z",
      "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
      "name": "Poison Ivy"
    }
  ]
}
```

Welcome to STIX 2! Sharing threat intelligence just got easier.

This page is just a basic outline of the STIX 2.0 data model. If you're looking for an introduction or conceptual overview of STIX, see the [full specification](http://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html). There's also the [documentation website](https://oasis-open.github.io/cti-documentation/) if you're looking for more examples and walkthroughs.

This documentation is divided into three major sections&hellip;

**Core Objects**

Start here. This is the description for the main objects in STIX. It's divided into domain objects (things like malware instances, campaigns, and indicators) and relationship objects (relationship itself, and sighting). Bundle is used to carry around all of the other objects, and Marking Definition lets you apply handling statements to them.

**Vocabularies**

Many of the core objects contain properties that let you pick from a list of values. These vocabularies define those lists. In most cases, you don't actually have to use a value from the vocabulary, it's just recommended to improve compatibility.

**Common Types**

These common types are used by the core objects (and sometimes by other common types).

# Core Objects

## Attack Pattern

> A generic attack pattern for spear phishing, referencing CAPEC:

```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
  "created": "2016-05-12T08:17:27.000Z",
  "modified": "2016-05-12T08:17:27.000Z",
  "name": "Spear Phishing",
  "description": "...",
  "external_references": [
    {
      "source_name": "capec",
      "external_id": "CAPEC-163"
    }
  ]
}
```

> A specific attack pattern for a particular form of spear phishing, referencing CAPEC:

```json
[
  {
    "type": "attack-pattern",
    "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "name": "Spear Phishing as Practiced by Adversary X",
    "description": "A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    "external_references": [
      {
        "source_name": "capec",
        "id": "CAPEC-163"
      }
    ]
  },
  {
    "type": "relationship",
    "id": "relationship--57b56a43-b8b0-4cba-9deb-34e3e1faed9e",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "relationship_type": "uses",
    "source_ref": "intrusion-set--0c7e22ad-b099-4dc3-b0df-2ea3f49ae2e6",
    "target_ref": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5"
  },
  {
    "type": "intrusion-set",
    "id": "intrusion-set--0c7e22ad-b099-4dc3-b0df-2ea3f49ae2e6",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "name": "Adversary X"
  }
]
```

**Type Name**: `attack-pattern`

Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed. An example of an attack pattern is "spear phishing": a common type of attack where an attacker sends a carefully crafted e-mail message to a party with the intent of getting them to click a link or open an attachment to deliver malware. Attack Patterns can also be more specific; spear phishing as practiced by a particular threat actor (e.g., they might generally say that the target won a contest) can also be an Attack Pattern.

The Attack Pattern SDO contains textual descriptions of the pattern along with references to externally-defined taxonomies of attacks such as CAPEC. Relationships from Attack Pattern can be used to relate it to what it targets (Vulnerabilities and Identities) and which tools and malware use it (Tool and Malware).

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of property field **MUST** be `attack-pattern`.
| **external_references** (optional) | [list](#list) of type [external-reference](#external-reference) | A list of external references which refer to non-STIX information. This property **MAY** be used to provide one or more Attack Pattern identifiers, such as a CAPEC ID. When specifying a CAPEC ID, the **source_name** property of the external reference **MUST** be set to `capec` and the **external_id** property **MUST** be formatted as CAPEC-[id]. |
| **name** (required) | [string](#string) | A name used to identify the Attack Pattern. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Attack Pattern, potentially including its purpose and its key characteristics. |
| **kill_chain_phases** (optional) | [list](#list) of type [kill-chain-phase](#kill-chain-phase) | The list of Kill Chain Phases for which this Attack Pattern is used.

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `attack-pattern` | `targets` | `identity`, `vulnerability` | This Relationship describes that this Attack Pattern typically targets the type of victims or vulnerability represented by the related Identity or Vulnerability object. For example, a `targets` Relationship linking an Attack Pattern for SQL injection to an Identity object representing domain administrators means that the form of SQL injection characterized by the Attack Pattern targets domain administrators in order to achieve its objectives. Another example is a Relationship linking an Attack Pattern for SQL injection to a Vulnerability in blogging software means that the particular SQL injection attack exploits that vulnerability.|
| `attack-pattern` | `uses` | `malware`, `tool` | This Relationship describes that the related Malware or Tool is used to perform the behavior identified in the Attack Pattern. For example, a `uses` Relationship linking an Attack Pattern for a distributed denial of service (DDoS) to a Tool for Low Orbit Ion Cannon (LOIC) indicates that the tool can be used to perform those DDoS attacks. |
| `indicator` | `indicates` | `attack-pattern` | This Relationship describes that the Indicator can detect evidence of the related Attack Pattern. This evidence may not be direct: for example, the Indicator may detect secondary evidence of the Attack Pattern, such as behavioral artifacts commonly associated with it.
| `course-of-action` | `mitigates` | `attack-pattern` | This Relationship describes that the Course of Action can mitigate the related Attack Pattern.
| `campaign`, `intrusion-set`, `threat-actor` | `uses` | `attack-pattern` | This Relationship describes that attacks carried out as part of the Campaign, Intrusion Set, or Threat Actor typically use the related Attack Pattern. For example, a `uses` Relationship from the Glass Gazelle Campaign to the Spear Phishing Attack Pattern indicates that Spear Phishing is often used during attacks attributed to that Campaign. |

## Campaign

> A basic campaign:

```json
{
  "type": "campaign",
  "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "name": "Green Group Attacks Against Finance",
  "description": "Campaign by Green Group against a series of targets in the financial services sector."
}
```

**Type Name**: `campaign`

A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set.

Campaigns are often attributed to an intrusion set and threat actors. The threat actors may reuse known infrastructure from the intrusion set or may set up new infrastructure specific for conducting that campaign.

Campaigns can be characterized by their objectives and the incidents they cause, people or resources they target, and the resources (infrastructure, intelligence, Malware, Tools, etc.) they use.

For example, a Campaign could be used to describe a crime syndicate's attack using a specific variant of malware and new C2 servers against the executives of ACME Bank during the summer of 2016 in order to gain secret information about an upcoming merger with another bank.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of property field **MUST** be `campaign`.
| **name** (required) | [string](#string) | A name used to identify the Campaign. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Campaign, potentially including its purpose and its key characteristics. |
| **kill_chain_phases** (optional) | [list](#list) of type [kill-chain-phase](#kill-chain-phase) | The list of Kill Chain Phases for which this Attack Pattern is used. |
| **aliases** (optional) | [list](#list) of type [string](#string) | Alternative names used to identify this Campaign
| **first_seen** (optional) | [timestamp](#timestamp) | The time that this Campaign was first seen. This property is a summary property of data from sightings and other data that may or may not be available in STIX. If new sightings are received that are earlier than the first seen timestamp, the object may be updated to account for the new data.
| **last_seen** (optional) | [timestamp](#timestamp) | The time that this Campaign was last seen. This property is a summary property of data from sightings and other data that may or may not be available in STIX. If new sightings are received that are later than the last seen timestamp, the object may be updated to account for the new data.
| **objective** (optional) | [string](#string) | This property defines the Campaign’s primary goal, objective, desired outcome, or intended effect — what the Threat Actor hopes to accomplish with this Campaign.

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `campaign` | `attributed-to` | `intrusion-set`, `threat-actor` | This Relationship describes that the Intrusion Set or Threat Actor that is involved in carrying out the Campaign. For example, an `attributed-to` Relationship from the Glass Gazelle Campaign to the Urban Fowl Threat Actor means that the actor carried out or was involved in some of the activity described by the Campaign.
| `campaign` | `targets` | `identity`, `vulnerability` | This Relationship describes that the Campaign uses exploits of the related Vulnerability or targets the type of victims described by the related Identity. For example, a `targets` Relationship from the Glass Gazelle Campaign to a Vulnerability in a blogging platform indicates that attacks performed as part of Glass Gazelle often exploit that Vulnerability. Similarly, a targets Relationship from the Glass Gazelle Campaign to a Identity describing the energy sector in the United States means that the Campaign typically carries out attacks against targets in that sector.
| `campaign `| `uses` | `attack-pattern`, `malware`, `tool` | This Relationship describes that attacks carried out as part of the Campaign typically use the related Attack Pattern, Malware, or Tool. For example, a `uses` Relationship from the Glass Gazelle Campaign to the xInject Malware indicates that xInject is often used during attacks attributed to that Campaign.
| `indicator` | `indicates` | `campaign` | This Relationship describes that the Indicator can detect evidence of the related Campaign. This evidence may not be direct: for example, the Indicator may detect secondary evidence of the Campaign, such as behavioral artifacts commonly associated with that actor.

## Course of Action

> A course of action mitigating a malware instance:

```json
[
  {
    "type": "course-of-action",
    "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
    "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
  },
  {
    "type": "relationship",
    "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:07:10.000Z",
    "modified": "2016-04-06T20:07:10.000Z",
    "relationship_type": "mitigates",
    "source_ref": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
  },
  {
    "type": "malware",
    "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:07:09.000Z",
    "modified": "2016-04-06T20:07:09.000Z",
    "name": "Poison Ivy"
  }
]
```

**Type Name**: `course-of-action`

<b>Note: The Course of Action object in STIX 2.0 is a stub. It is included to support basic use cases (such as sharing prose courses of action) but does not support the ability to represent automated courses of action or contain properties to represent metadata about courses of action. Future STIX 2 releases will expand it to include these capabilities.</b>

A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes. For example, a course of action to mitigate a vulnerability could describe applying the patch that fixes it.

The Course of Action SDO contains a textual description of the action; a reserved action property also serves as placeholder for future inclusion of machine automatable courses of action. Relationships from the Course of Action can be used to link it to the Vulnerabilities or behaviors (Tool, Malware, Attack Pattern) that it mitigates.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of property field **MUST** be `course-of-action`.
| **name** (required) | [string](#string) | A name used to identify the Course of Action. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Course of Action, potentially including its purpose and its key characteristics. |

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `course-of-action` | `mitigates` | `attack-pattern`, `malware`, `tool`, `vulnerability` | This Relationship describes that the Course of Action can mitigate the related Attack Pattern, Malware, Vulnerability, or Tool. For example, a `mitigates` Relationship from a Course of Action object to a Malware object indicates that the course of action mitigates the impact of that malware.

## Identity

> An Identity for an individual named John Smith:

```json
{
  "type": "identity",
  "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "name": "John Smith",
  "identity_class": "individual"
}
```

> An Identity for a company named ACME Widget, Inc.:

```json
{
  "type": "identity",
  "id": "identity--e5f1b90a-d9b6-40ab-81a9-8a29df4b6b65",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "name": "ACME Widget, Inc.",
  "identity_class": "organization"
}
```

**Type Name**: `identity`

Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, or groups (e.g., the finance sector).

The Identity SDO can capture basic identifying information, contact information, and the sectors that the Identity belongs to. Identity is used in STIX to represent, among other things, targets of attacks, information sources, object creators, and threat actor identities.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of property field **MUST** be `identity`.
| **labels** (required) | [list](#list) of type [string](#string) | The list of roles that this Identity performs (e.g., CEO, Domain Administrators, Doctors, Hospital, or Retailer). No open vocabulary is yet defined for this property.
| **name** (required) | [string](#string) | The name of this Identity. When referring to a specific entity (e.g., an individual or organization), this property **SHOULD** contain the canonical name of the specific entity. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Identity, potentially including its purpose and its key characteristics. |
| **identity_class** (required) | [open-vocab](#open-vocab) | The type of entity that this Identity describes, e.g., an individual or organization. This is an open vocabulary and the values **SHOULD** come from the [identity-class-ov](#identity-class) vocabulary.
| **sectors** (optional) | [list](#list) of type [open-vocab](#open-vocab) | The list of industry sectors that this Identity belongs to. This is an open vocabulary and values **SHOULD** come from the [industry-sector-ov](#industry-sector) vocabulary. |
| **contact_information** (optional) | [string](#string) | The contact information (e-mail, phone number, etc.) for this Identity.  No format for this information is currently defined by this specification. |

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `attack-pattern`, `campaign`, `intrusion-set`, `malware`, `threat-actor`, `tool` | `targets` | `identity` | This Relationship describes that the Attack Pattern typically targets the type of victims represented by the related Identity. For example, a targets Relationship linking an Attack Pattern for SQL injection to an Identity object representing domain administrators means that the form of SQL injection characterized by the Attack Pattern targets domain administrators in order to achieve its objectives. |
| `threat-actor` | `attributed-to` | `identity` | This Relationship describes that the Threat Actor's real identity is the related Identity. For example, an attributed-to Relationship from the jay-sm17h Threat Actor to the John Smith Identity means that the actor known as jay-sm17h is John Smith. |
| `threat-actor` | `impersonates` | `identity` | This Relationship describes that the Threat Actor impersonates the related Identity. For example, an  impersonates Relationship from the gh0st Threat Actor to the ACME Corp. Identity means that the actor known as gh0st impersonates ACME Corp. |

## Indicator

> Indicator itself, with context:

```json
[
  {
    "type": "indicator",
    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "labels": ["malicious-activity"],
    "name": "Poison Ivy Malware",
    "description": "This file is part of Poison Ivy",
    "pattern": "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
    "valid_from": "2016-01-01T00:00:00Z"
  },
  {
    "type": "relationship",
    "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:06:37.000Z",
    "modified": "2016-04-06T20:06:37.000Z",
    "relationship_type": "indicates",
    "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
  },
  {
    "type": "malware",
    "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
    "created": "2016-04-06T20:07:09.000Z",
    "modified": "2016-04-06T20:07:09.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "name": "Poison Ivy"
  }
]
```

**Type Name**: `indicator`

Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity. For example, an Indicator may be used to represent a set of malicious domains and use the STIX Patterning Language (STIX™ Version 2.0. Part 5: STIX Patterning) to specify these domains.

The Indicator SDO contains a simple textual description, the Kill Chain Phases that it detects behavior in, a time window for when the Indicator is valid or useful, and a required pattern property to capture a structured detection pattern. Conforming STIX implementations **MUST** support the STIX Patterning Language as defined in STIX™ Version 2.0. Part 5: STIX Patterning. While each structured pattern language has different syntax and potentially different  semantics, in general an Indicator is considered to have "matched" (or been "sighted") when the conditions specified in the structured pattern are satisfied in whatever context they are evaluated in.

Relationships from the Indicator can describe the malicious or suspicious behavior that it directly detects (Malware, Tool, and Attack Pattern) as well as the Campaigns, Intrusion Sets, and Threat Actors that it might indicate the presence of.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `indicator`. |
| **labels** (required) | [list](#list) of type [open-vocab](#open-vocab) | Specifies the type of indicator. This is an open vocabulary and values **SHOULD** come from the [indicator-label-ov](#indicator-label) vocabulary.
| **name** (optional) | [string](#string) | A name used to identify the Indicator. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Indicator, potentially including its purpose and its key characteristics. |
| **pattern** (required) | [string](#string) | The detection pattern for this Indicator is a STIX Pattern as specified in STIX™ Version 2.0. Part 5: STIX Patterning. |
| **valid_from** (required) | [timestamp](#timestamp) | The time from which this Indicator should be considered valuable intelligence. |
| **valid_until** (optional) | [timestamp](#timestamp) | The time at which this Indicator should no longer be considered valuable intelligence. If the **valid_until** property is omitted, then there is no constraint on the latest time for which the Indicator should be used. |
| **kill_chain_phases** (optional) | [list](#list) of type [kill-chain-phase](#kill-chain-phase) | The kill chain phase(s) to which this Indicator corresponds. |

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `indicator` | `indicates` | `attack-pattern`, `campaign`, `intrusion-set`, `malware`, `threat-actor`, `tool` | This Relationship describes that the Indicator can detect evidence of the related Campaign, Intrusion Set, or Threat Actor. This evidence may not be direct: for example, the Indicator may detect secondary evidence of the Campaign, such as malware or behavior commonly used by that Campaign. For example, an indicates Relationship from an Indicator to a Campaign object representing Glass Gazelle means that the Indicator is capable of detecting evidence of Glass Gazelle, such as command and control IPs commonly used by that Campaign. |

## Intrusion Set

> Examples:

```json
{
  "type": "intrusion-set",
  "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "name": "Bobcat Breakin",
  "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.",
  "aliases": ["Zookeeper"],
  "goals": ["acquisition-theft", "harassment", "damage"]
}
```

**Type Name**: `intrusion-set`

An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization. An Intrusion Set may capture multiple Campaigns or other activities that are all tied together by shared attributes indicating a common known or unknown Threat Actor. New activity can be attributed to an Intrusion Set even if the Threat Actors behind the attack are not known. Threat Actors can move from supporting one Intrusion Set to supporting another, or they may support multiple Intrusion Sets.

Where a Campaign is a set of attacks over a period of time against a specific set of targets to achieve some objective, an Intrusion Set is the entire attack package and may be used over a very long period of time in multiple Campaigns to achieve potentially multiple purposes.

While sometimes an Intrusion Set is not active, or changes focus, it is usually difficult to know if it has truly disappeared or ended. Analysts may have varying level of fidelity on attributing an Intrusion Set back to Threat Actors and may be able to only attribute it back to a nation state or perhaps back to an organization within that nation state.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `intrusion-set`.
| **name** (required) | [string](#string) | A name used to identify this Intrusion Set.
| **description** (optional) | [string](#string) | A description that provides more details and context about the Intrusion Set, potentially including its purpose and its key characteristics.
| **aliases** (optional) | [list](#list) of type [string](#string) | Alternative names used to identify this Intrusion Set.
| **first_seen** (optional) | [timestamp](#timestamp) | The time that this Intrusion Set was first seen. This property is a summary property of data from sightings and other data that may or may not be available in STIX. If new sightings are received that are earlier than the first seen timestamp, the object may be updated to account for the new data.
| **last_seen** (optional) | [timestamp](#timestamp) | The time that this Intrusion Set was last seen. This property is a summary property of data from sightings and other data that may or may not be available in STIX. If new sightings are received that are later than the last seen timestamp, the object may be updated to account for the new data.
| **goals** (optional) | [list](#list) of type [string](#string) | The high level goals of this Intrusion Set, namely, what are they trying to do. For example, they may be motivated by personal gain, but their goal is to steal credit card numbers. To do this, they may execute specific Campaigns that have detailed objectives like compromising point of sale systems at a large retailer. Another example: to gain information about latest merger and IPO information from ACME Bank.
| **resource_level** (optional) | [open-vocab](#open-vocab) | This defines the organizational level at which this Intrusion Set typically works, which in turn determines the resources available to this Intrusion Set for use in an attack. This is an open vocabulary and values **SHOULD** come from the [attack-resource-level-ov](#attack-resource-level) vocabulary.
| **primary_motivation** (optional) | [open-vocab](#open-vocab) | The primary reason, motivation, or purpose behind this Intrusion Set. The motivation is why the Intrusion Set wishes to achieve the goal (what they are trying to achieve). For example, an Intrusion Set with a goal to disrupt the finance sector in a country might be motivated by ideological hatred of capitalism. This is an open vocabulary and values **SHOULD** come from the [attack-motivation-ov](#attack-motivation) vocabulary.
| **secondary_motivations** (optional) | [list](#list) of type [open-vocab](#open-vocab) | The secondary reasons, motivations, or purposes behind this Intrusion Set. These motivations can exist as an equal or near-equal cause to the primary motivation. However, it does not replace or necessarily magnify the primary motivation, but it might indicate additional context. This is an open vocabulary and values **SHOULD** come from the [attack-motivation-ov](#attack-motivation) vocabulary.

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `campaign` | `attributed-to` | `intrusion-set` | This Relationship describes that the Intrusion Set is involved in carrying out the Campaign. For example, an `attributed-to` Relationship from the Glass Gazelle Campaign to the Urban Fowl Threat Actor means that the actor carried out or was involved in some of the activity described by the Campaign.
| `indicator` | `indicates` | `intrusion-set` | This Relationship describes that the Indicator can detect evidence of the related Intrusion Set. This evidence may not be direct: for example, the Indicator may detect secondary evidence of the Intrusion Set, such as malware or behavior commonly used by that Intrusion Set. For example, an indicates Relationship from an Indicator to a Intrusion Set object representing Glass Gazelle means that the Indicator is capable of detecting evidence of Glass Gazelle, such as command and control IPs commonly used by that Intrusion Set. |
| `intrusion-set` | `attributed-to` | `threat-actor` | This Relationship describes that the related Threat Actor is involved in carrying out the Intrusion Set. For example, an `attributed-to` Relationship from the Red Orca Intrusion Set to the Urban Fowl Threat Actor means that the actor carried out or was involved in some of the activity described by the Intrusion Set. |
| `intrusion-set` | `targets` | `identity`, `vulnerability` | This Relationship describes that the Intrusion Set uses exploits of the related Vulnerability or targets the type of victims described by the related Identity. For example, a `targets` Relationship from the Red Orca Intrusion Set to a Vulnerability in a blogging platform indicates that attacks performed as part of Red Orca often exploit that Vulnerability. Similarly, a targets Relationship from the Red Orca Intrusion Set to an Identity describing the energy sector in the United States means that the Intrusion Set typically carries out attacks against targets in that sector. |
| `intrusion-set` | `uses` | `attack-pattern`, `malware`, `tool` | This Relationship describes that attacks carried out as part of the Intrusion Set typically use the related Attack Pattern, Malware, or Tool. For example, a `uses` Relationship from the Red Orca Intrusion Set to the xInject Malware indicates that xInject is often used during attacks attributed to that Intrusion Set. |

## Malware

> Example malware family:

```json
{
  "type": "malware",
  "id": "malware--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
  "created": "2016-05-12T08:17:27.000Z",
  "modified": "2016-05-12T08:17:27.000Z",
  "name": "Cryptolocker",
  "description": "...",
  "labels": ["ransomware"]
}
```

<b>Note: The Malware object in STIX 2.0 is a stub. It is included to support basic use cases but is likely not useful for actual malware analysis or for including even simple malware instance data. Future versions of STIX 2 will expand it to include these capabilities.</b>

Malware is a type of TTP that is also known as malicious code and malicious software, and refers to a program that is inserted into a system, usually covertly, with the intent of compromising the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or of otherwise annoying or disrupting the victim. Malware such as viruses and worms are usually designed to perform these nefarious functions in such a way that users are unaware of them, at least initially.

The Malware SDO characterizes, identifies, and categorizes malware samples and families via a text description property. This provides detailed information about how the malware works and what it does. Relationships from Malware can capture what the malware targets (Vulnerability and Identity) and link it to another Malware SDO that it is a variant of.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `malware`. |
| **labels** (required) | [list](#list) of type [open-vocab](#open-vocab) | The type of malware being described. This is an open vocabulary and values **SHOULD** come from the [malware-label-ov](#malware-label) vocabulary.
| **name** (optional) | [string](#string) | A name used to identify the Malware sample.
| **description** (optional) | [string](#string) | A description that provides more details and context about the Malware, potentially including its purpose and its key characteristics.
| **kill_chain_phases** (optional) | [list](#list) of type [kill-chain-phase](#kill-chain-phase) | The list of Kill Chain Phases for which this Malware can be used. |

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `attack-pattern`, `campaign`, `intrusion-set`, `threat-actor` | `uses` | `malware` | This Relationship describes that the related Malware is used to perform the behavior identified in the Attack Pattern. |
| `course-of-action` | `mitigates` | `malware` | This Relationship describes that the Course of Action can mitigate the related Malware. |
| `indicator` | `indicates` | `malware` | This Relationship describes that the Indicator can detect evidence of the related Malware. |
| `malware` | `targets` | `identity`, `vulnerability` | This Relationship documents that this Malware is being used to target this Identity or exploit the Vulnerability. For example, a `targets` Relationship linking a Malware representing a downloader to a Vulnerability for CVE-2016-0001 means that the malware exploits that vulnerability. Similarly, a targets Relationship linking a Malware representing a downloader to an Identity representing the energy sector means that downloader is typically used against targets in the energy sector. |
| `malware` | `uses` | `tool` | This Relationship documents that this Malware uses the related tool to perform its functions. |
| `malware` | `variant-of` | `malware` | This Relationship is used to document that one piece of Malware is a variant of another piece of Malware. For example, TorrentLocker is a variant of CryptoLocker. |

## Observed Data

> Observed Data of a file object:

```json
{
  "type": "observed-data",
  "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T19:58:16.000Z",
  "modified": "2016-04-06T19:58:16.000Z",
  "first_observed": "2015-12-21T19:00:00Z",
  "last_observed": "2015-12-21T19:00:00Z",
  "number_observed": 50,
  "objects": {
    "0": {
      "type": "file",
      ...
    }
  }
}
```

Observed Data conveys information that was observed on systems and networks using the Cyber Observable specification defined in parts 3 and 4 of this specification. For example, Observed Data can capture the observation of an IP address, a network connection, a file, or a registry key. Observed Data is not an intelligence assertion, it is simply information: this file was seen, without any context for what it means.

Observed Data captures both a single observation of a single entity (file, network connection) as well as the aggregation of multiple observations of an entity. When the **number_observed** property is 1 the Observed Data is of a single entity. When the **number_observed** property is greater than 1, the observed data consists of several instances of an entity collected over the time window specified by the **first_observed** and **last_observed** properties. When used to collect aggregate data, it is likely that some fields in the Cyber Observable Object (e.g., timestamp fields) will be omitted because they would differ for each of the individual observations.

Observed Data may be used by itself (without relationships) to convey raw data collected from network and host-based detection tools. A firewall could emit a single Observed Data instance containing a single Network Traffic object for each connection it sees. The firewall could also aggregate data and instead send out an Observed Data instance every ten minutes with an IP address and an appropriate number_observed value to indicate the number of times that IP address was observed in that window.

Observed Data may also be related to other SDOs to represent raw data that is relevant to those objects. The Sighting object, which captures the sighting of an Indicator, Malware, or other SDO, uses Observed Data to represent the raw information that led to the creation of the Sighting (e.g., what was actually seen that suggested that a particular instance of malware was active).

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `observed-data`. |
| **first_observed** (required) | [](#timestamp) | The beginning of the time window during which the data was observed. |
| **last_observed** (required) | [timestamp](#timestamp) | The end of the time window during which the data was observed. |
| **number_observed** (required) | [integer](#integer) | The number of times the data represented in the objects property was observed. This **MUST** be an integer between 1 and 999,999,999 inclusive. If the **number_observed** property is greater than 1, the data contained in the objects property was observed multiple times. In these cases, object creators **MAY** omit properties of the Cyber Observable object (such as timestamps) that are specific to a single instance of that observed data. |
| **objects** (required) | observable-objects | A dictionary of Cyber Observable Objects representing the observation. The dictionary **MUST** contain at least one object. The `observable-objects` type is defined in STIX™ Version 2.0. Part 3: Cyber Observable Core Concepts. The Cyber Observable content **MAY** include multiple objects if those objects are related as part of a single observation. Multiple objects not related to each other via Cyber Observable Relationships **MUST NOT** be contained within the same Observed Data instance. For example, a Network Traffic object and two IPv4 Address objects related via the src_ref and dst_ref properties can be contained in the same Observed Data because they are all related and used to characterize that single entity. Two unrelated IPv4 address objects that just happened to be observed at the same time, however, must be represented in separate Observed Data instances.

### Relationships

There are no relationships explicitly defined between the Observed Data object and other objects, other than those defined as common relationships. The first section lists the embedded relationships by property name along with their corresponding target.

## Relationship

The Relationship object is used to link together two SDOs (objects other than Sighting, Relationship, Bundle, and Data Marking) in order to describe how they are related to each other. If SDOs are considered "nodes" or "vertices" in the graph, the Relationship Objects (SROs) represent "edges".

STIX defines many relationship types to link together SDOs. These relationships are contained in the "Relationships" table under each SDO definition. Relationship types defined in the specification **SHOULD** be used to ensure consistency. An example of a specification-defined relationship is that an indicator indicates a campaign. That relationship type is listed in the Relationships section of the Indicator SDO definition.

STIX also allows relationships from any SDO to any SDO that have not been defined in this specification. These relationships **MAY** use the `related-to` relationship type or **MAY** use a custom relationship type. As an example, a user might want to link malware directly to a tool. They can do so using `related-to` to say that the Malware is related to the Tool but not describe how, or they could use `delivered-by` (a custom name they determined) to indicate more detail.

Note that some relationships in STIX may seem like "shortcuts". For example, an Indicator doesn't really detect a Campaign: it detects activity (Attack Patterns, Malware, etc.) that are often used by that campaign. While some analysts might want all of the source data and think that shortcuts are misleading, in many cases it's helpful to provide just the key points (shortcuts) and leave out the low-level details. In other cases, the low-level analysis may not be known or sharable, while the high-level analysis is. For these reasons, relationships that might appear to be "shortcuts" are not excluded from STIX.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **relationship_type** (required) | [string](#string) | The name used to identify the type of Relationship. This value **SHOULD** be an exact value listed in the relationships for the source and target SDO, but **MAY** be any string. The value of this property **MUST** be in ASCII and is limited to characters a–z (lowercase ASCII), 0–9, and hyphen (-). |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Relationship, potentially including its purpose and its key characteristics. |
| **source_ref** (required) | [identifier](#identifier) | The id of the source (from) object. The value **MUST** be an ID reference to an SDO (i.e., it cannot point to an SRO, Bundle, or Marking Definition). |
| **target_ref** (required) | [identifier](#identifier) | The id of the target (to) object. The value **MUST** be an ID reference to an SDO (i.e., it cannot point to an SRO, Bundle, or Marking Definition). |

### Relationships

There are no relationships between the Relationship object and other objects, other than the embedded relationships listed below by property name along with their corresponding target.

## Report

> A standalone Report; the consumer may or may not already have access to the referenced STIX Objects:

```json
{
  "type": "report",   
  "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
  "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
  "created": "2015-12-21T19:59:11.000Z",
  "modified": "2015-12-21T19:59:11.000Z",
  "name": "The Black Vine Cyberespionage Group",
  "description": "A simple report with an indicator and campaign",
  "published": "2016-01-20T17:00:00.000Z",
  "labels": ["campaign"],
  "object_refs": [
    "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
    "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
    "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
  ]
}
```

> A Bundle with a Report and the STIX Objects that are referred to by the Report:

```json
{
  "type": "bundle",
  "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
  "objects": [
    {
      "type": "identity",
      "id": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
      ...,
      "name": "Acme Cybersecurity Solutions"
    },
    {
      "type": "report",   
      "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcbd",
      "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
      "created": "2015-12-21T19:59:11.000Z",
      "modified": "2016-05-21T19:59:11.000Z",
      "name": "The Black Vine Cyberespionage Group",
      "description": "A simple report with an indicator and campaign",
      "published": "2016-01-201T17:00:00Z",
      "labels": ["campaign"],
      "object_refs": [
        "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
        "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
        "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
      ]
    },
    {
      "type": "indicator",
      "id": "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
      "created": "2015-12-21T19:59:17.000Z",
      "modified": "2016-05-21T19:59:17.000Z",
      "name": "Some indicator",
      "labels": ["malicious-activity"],
      "pattern": "[ file:hashes.MD5 = '3773a88f65a5e780c8dff9cdc3a056f3' ]",
      "valid_from": "2015-12-21T19:59:17Z",
      "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283"
    },
    {
      "type": "campaign",
      "id": "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
      "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
      "created": "2015-12-21T19:59:17.000Z",
      "modified": "2016-05-21T19:59:17.000Z",
      "name": "Some Campaign"
    },
    {
      "type": "relationship",
      "id": "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
      "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
      "created": "2015-12-21T19:59:17.000Z",
      "modified": "2015-12-21T19:59:17.000Z",
      "source_ref": "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
      "target_ref": "campaign--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
      "relationship_type": "indicates"
    }
  ]
}
```

Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and related details. They are used to group related threat intelligence together so that it can be published as a comprehensive cyber threat story.

The Report SDO contains a list of references to SDOs and SROs (the CTI objects included in the report) along with a textual description and the name of the report.

For example, a threat report produced by ACME Defense Corp. discussing the Glass Gazelle campaign should be represented using Report. The Report itself would contain the narrative of the report while the Campaign SDO and any related SDOs (e.g., Indicators for the Campaign, Malware it uses, and the associated Relationships) would be referenced in the report contents.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `report`. |
| **labels** (required) | [list](#list) of type [open-vocab](#open-vocab) | This property is an Open Vocabulary that specifies the primary subject of this report. This is an open vocabulary and values **SHOULD** come from the [report-label-ov](#report-label) vocabulary. |
| **name** (required) | [string](#string) | A name used to identify the Report. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Report, potentially including its purpose and its key characteristics. |
| **published** (required) | [timestamp](#timestamp) | The date that this Report object was officially published by the creator of this report. The publication date (public release, legal release, etc.) may be different than the date the report was created or shared internally (the date in the created property). |
| **object_refs** (required) | [list](#list) of type [identifier](#identifier) | Specifies the STIX Objects that are referred to by this Report. |

### Relationships

There are no relationships explicitly defined between the Report object and other objects, other than those defined as common relationships.

## Sighting

> Sighting of Indicator, without Observed Data:

```json
{
  "type": "sighting",
  "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:08:31.000Z",
  "modified": "2016-04-06T20:08:31.000Z",
  "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
}
```

> Sighting of Indicator, with Observed Data (what exactly was seen) and where it was seen:

```json
[
  {
    "type": "sighting",
    "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:08:31.000Z",
    "modified": "2016-04-06T20:08:31.000Z",
    "first_seen": "2015-12-21T19:00:00Z",
    "last_seen": "2015-12-21T19:00:00Z",
    "count": 50,
    "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "observed_data_refs": ["observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"],
    "where_sighted_refs": ["identity--b67d30ff-02ac-498a-92f9-32f845f448ff"]
  },
  {
    "type": "observed-data",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T19:58:16.000Z",
    "modified": "2016-04-06T19:58:16.000Z",
    "start": "2015-12-21T19:00:00Z",
    "stop": "2016-04-06T19:58:16Z",
    "count": 50,
    "objects": {
      "0": {
        "type": "file",
        ...
      }
    }
  }
]
```

A Sighting denotes the belief that something in CTI (e.g., an indicator, malware, tool, threat actor, etc.) was seen. Sightings are used to track who and what are being targeted, how attacks are carried out, and to track trends in attack behavior.

The Sighting relationship object is a special type of SRO; it is a relationship that contains extra properties not present on the generic Relationship object. These extra properties are included to represent data specific to sighting relationships (e.g., count, representing how many times something was seen), but for other purposes a Sighting can be thought of as a Relationship with a name of "sighting-of". Sighting is captured as a relationship because you cannot have a sighting unless you have something that has been sighted. Sighting does not make sense without the relationship to what was sighted.

Sighting relationships relate three aspects of the sighting:
* What was sighted, such as the Indicator, Malware, Campaign, or other SDO (**sighting_of_ref**)
* Who sighted it and/or where it was sighted, represented as an Identity (**where_sighted_refs**) and
* What was actually seen on systems and networks, represented as Observed Data (**observed_data_refs**)

What was sighted is required; a sighting does not make sense unless you say what you saw. Who sighted it, where it was sighted, and what was actually seen are optional. In many cases it is not necessary to provide that level of detail in order to provide value.

Sightings are used whenever any SDO has been "seen". In some cases, the object creator wishes to convey very little information about the sighting; the details might be sensitive, but the fact that they saw a malware instance or threat actor could still be very useful. In other cases, providing the details may be helpful or even necessary; saying exactly which of the 1000 IP addresses in an indicator were sighted is helpful when tracking which of those IPs is still malicious.

Sighting is distinct from Observed Data in that Sighting is an intelligence assertion ("I saw this threat actor") while Observed Data is simply information ("I saw this file"). When you combine them by including the linked Observed Data (**observed_data_refs**) from a Sighting, you can say "I saw this file, and that makes me think I saw this threat actor". Although confidence is currently reserved, notionally confidence would be added to Sighting (the intelligence relationship) but not to Observed Data (the raw information).

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `sighting`.
| **first_seen** (optional) | [timestamp](#timestamp) | The beginning of the time window during which the SDO referenced by the sighting_of_ref property was sighted.
| **last_seen** (optional) | [timestamp](#timestamp) | The end of the time window during which the SDO referenced by the sighting_of_ref property was sighted.
| **count** (optional) | [integer](#integer) | This **MUST** be an integer between 0 and 999,999,999 inclusive and represents the number of times the SDO referenced by the **sighting_of_ref** property was sighted. Observed Data has a similar property called **number_observed**, which refers to the number of times the data was observed. These counts refer to different concepts and are distinct. For example, a single sighting of a DDoS bot might have many millions of observations of the network traffic that it generates. Thus, the Sighting count would be `1` (the bot was observed once) but the Observed Data **number_observed** would be much higher. As another example, a sighting with a count of 0 can be used to express that an indicator was not seen at all.
| **sighting_of_ref** (required) | [identifier](#identifier) | An ID reference to the SDO that was sighted (e.g., Indicator or Malware). For example, if this is a Sighting of an Indicator, that Indicator’s ID would be the value of this property. This property **MUST** reference only an SDO or a Custom Object.
| **observed_data_refs** (optional) | [list](#list) of type [identifier](#identifier) | A list of ID references to the Observed Data objects that contain the raw cyber data for this Sighting. For example, a Sighting of an Indicator with an IP address could include the Observed Data for the network connection that the Indicator was used to detect. This property **MUST** reference only Observed Data SDOs.
| **where_sighted_refs** (optional) | [list](#list) of type [identifier](#identifier) | A list of ID references to the Identity (victim) objects of the entities that saw the sighting. Omitting the **where_sighted_refs** property does not imply that the sighting was seen by the object creator. To indicate that the sighting was seen by the object creator, an Identity representing the object creator should be listed in **where_sighted_refs**. This property **MUST** reference only Identity SDOs.
| **summary** (optional) | [boolean](#boolean) | The summary property indicates whether the Sighting should be considered summary data. Summary data is an aggregation of previous Sightings reports and should not be considered primary source data. Default value is `false`.

### Relationships

There are no relationships between the Sighting object and other objects, other than the embedded relationships listed below by property name along with their corresponding target.

## Threat Actor

> Example:

```json
{
  "type": "threat-actor",
  "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "labels": [ "crime-syndicate"],
  "name": "Evil Org",
  "description": "The Evil Org threat actor group",
  "aliases": ["Syndicate 1", "Evil Syndicate 99"],
  "roles": "director",
  "goals": ["Steal bank money", "Steal credit cards"],
  "sophistication": "advanced",
  "resource_level": "team",
  "primary_motivation": "organizational-gain"
}
```

Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent. A Threat Actor is not an Intrusion Set but may support or be affiliated with various Intrusion Sets, groups, or organizations over time.
 
Threat Actors leverage their resources, and possibly the resources of an Intrusion Set, to conduct attacks and run Campaigns against targets.
 
Threat Actors can be characterized by their motives, capabilities, goals, sophistication level, past activities, resources they have access to, and their role in the organization.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | 
| **labels** (required) | [list](#list) of type [open-vocab](#open-vocab) | This property specifies the type of Threat Actor. This is an open vocabulary and values **SHOULD** come from the [threat-actor-label-ov](#threat-actor-label) vocabulary.
| **name** (required) | [string](#string) | A name used to identify this Threat Actor or Threat Actor group.
| **description** (optional) | [string](#string) | A description that provides more details and context about the Threat Actor, potentially including its purpose and its key characteristics.
| **aliases** (optional) | [list](#list) of type [string](#string) | A list of other names that this Threat Actor is believed to use.
| **roles** (optional) | [list](#list) of type [open-vocab](#open-vocab) | A list of roles the Threat Actor plays. This is an open vocabulary and the values **SHOULD** come from the [threat-actor-role-ov](#threat-actor-role) vocabulary.
| **goals** (optional) | [list](#list) of type [string](#string) | The high level goals of this Threat Actor, namely, what are they trying to do. For example, they may be motivated by personal gain, but their goal is to steal credit card numbers. To do this, they may execute specific Campaigns that have detailed objectives like compromising point of sale systems at a large retailer.
| **sophistication** (optional) | [open-vocab](#open-vocab) | The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack. This is an open vocabulary and values **SHOULD** come from the [threat-actor-sophistication-ov](#threat-actor-sophistication]) vocabulary.
| **resource_level** (optional) | [open-vocab](#open-vocab) | This defines the organizational level at which this Threat Actor typically works, which in turn determines the resources available to this Threat Actor for use in an attack. This attribute is linked to the sophistication property — a specific resource level implies that the Threat Actor has access to at least a specific sophistication level. This is an open vocabulary and values **SHOULD** come from the [attack-resource-level-ov](#attack-resource-level) vocabulary.
| **primary_motivation** (optional) | [open-vocab](#open-vocab) | The primary reason, motivation, or purpose behind this Threat Actor. The motivation is why the Threat Actor wishes to achieve the goal (what they are trying to achieve). For example, a Threat Actor with a goal to disrupt the finance sector in a country might be motivated by ideological hatred of capitalism. This is an open vocabulary and values **SHOULD** come from the [attack-motivation-ov](#attack-motivation) vocabulary.
| **secondary_motivations** (optional) | [list](#list) of type [open-vocab](#open-vocab) | The secondary reasons, motivations, or purposes behind this Threat Actor. These motivations can exist as an equal or near-equal cause to the primary motivation. However, it does not replace or necessarily magnify the primary motivation, but it might indicate additional context. This is an open vocabulary and values **SHOULD** come from the [attack-motivation-ov](#attack-motivation) vocabulary.
| **personal_motivations** (optional) | [list](#list) of type [open-vocab](#open-vocab) | The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals. Personal motivation, which is independent of the organization’s goals, describes what impels an individual to carry out an attack. Personal motivation may align with the organization’s motivation—as is common with activists—but more often it supports personal goals. For example, an individual analyst may join a Data Miner corporation because his or her skills may align with the corporation’s objectives. But the analyst most likely performs his or her daily work toward those objectives for personal reward in the form of a paycheck. The motivation of personal reward may be even stronger for Threat Actors who commit illegal acts, as it is more difficult for someone to cross that line purely for altruistic reasons. This is an open vocabulary and values **SHOULD** come from the [attack-motivation-ov](#attack-motivation) vocabulary.

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `campaign`, `intrusion-set` | `attributed-to` | `threat-actor` | This Relationship describes that the related Threat Actor is involved in carrying out the Intrusion Set. For example, an `attributed-to` Relationship from the Red Orca Intrusion Set to the Urban Fowl Threat Actor means that the actor carried out or was involved in some of the activity described by the Intrusion Set. |
| `indicator` | `indicates` | `threat-actor` | This Relationship describes that the Indicator can detect evidence of the related Threat Actor. This evidence may not be direct: for example, the Indicator may detect secondary evidence of the Threat Actor, such as malware or behavior commonly used by that actor. For example, an `indicates` Relationship from an Indicator to a Threat Actor object representing Glass Gazelle means that the Indicator is capable of detecting evidence of Glass Gazelle, such as command and control IPs commonly used by that Threat Actor.
| `threat-actor` | `attributed-to` | `identity` | This Relationship describes that the Threat Actor's real identity is the related Identity. For example, an `attributed-to` Relationship from the jay-sm17h Threat Actor to the John Smith Identity means that the actor known as jay-sm17h is John Smith. |
| `threat-actor` | `impersonates` | `identity` | This Relationship describes that the Threat Actor impersonates the related Identity. For example, an  `impersonates` Relationship from the gh0st Threat Actor to the ACME Corp. Identity means that the actor known as gh0st impersonates ACME Corp. |
| `threat-actor` | `targets` | `identity`, `vulnerability` | This Relationship describes that the Threat Actor uses exploits of the related Vulnerability or targets the type of victims described by the related Identity. For example, a `targets` Relationship from the jay-sm17h Threat Actor to a Vulnerability in a blogging platform indicates that attacks performed by John Smith often exploit that Vulnerability. Similarly, a targets Relationship from the jay-sm17h Threat Actor to an Identity describing the energy sector in the United States means that John Smith often carries out attacks against targets in that sector. |
| `threat-actor` | `uses` | `attack-pattern`, `malware`, `tool` | This Relationship describes that attacks carried out as part of the Threat Actor typically use the related Attack Pattern, Malware, or Tool. For example, a `uses` Relationship from the jay-sm17h Threat Actor to the xInject Malware indicates that xInject is often used by John Smith. |

## Tool

> Example:

```json
{
  "type": "tool",
  "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "labels": [ "remote-access"],
  "name": "VNC"
}
```

Tools are legitimate software that can be used by threat actors to perform attacks. Knowing how and when threat actors use such tools can be important for understanding how campaigns are executed. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users. Remote access tools (e.g., RDP) and network scanning tools (e.g., Nmap) are examples of Tools that may be used by a Threat Actor during an attack.

The Tool SDO characterizes the properties of these software tools and can be used as a basis for making an assertion about how a Threat Actor uses them during an attack. It contains properties to name and describe the tool, a list of Kill Chain Phases the tool can be used to carry out, and the version of the tool.

This SDO **MUST NOT** be used to characterize malware. Further, Tool **MUST NOT** be used to characterise tools used as part of a course of action in response to an attack. Tools used during response activities can be included directly as part of a Course of Action SDO.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `tool`. |
| **labels** (required) | [list](#list) of type [open-vocab](#open-vocab) | The kind(s) of tool(s) being described. This is an open vocabulary and values **SHOULD** come from the [tool-label-ov](#tool-label) vocabulary. |
| **name** (optional) | [string](#string) | A name used to identify the Tool.
| **description** (optional) | [string](#string) | A description that provides more details and context about the Tool, potentially including its purpose and its key characteristics. |
| **kill_chain_phases** (optional) | [list](#list) of type [kill-chain-phase](#kill-chain-phase) | The list of kill chain phases for which this Tool can be used. |
| **tool_version** (optional) | [string](#string) | The version identifier associated with the Tool. |

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `attack-pattern`, `campaign`, `intrusion-set`, `malware` | `uses` | `tool` | This Relationship describes that the Attack Pattern, Campaign, Intrusion Set, or Malware uses the related Tool. For example, a `uses` Relationship linking an Attack Pattern for a distributed denial of service (DDoS) to a Tool for Low Orbit Ion Cannon (LOIC) indicates that the tool can be used to perform those DDoS attacks. |
| `course-of-action` | `mitigates` | `malware` | This Relationship describes that the Course of Action can mitigate the related Tool. |
| `indicator` | `indicates` | `tool` | This Relationship describes that the Indicator can detect evidence of the related Tool. |
| `tool` | `targets` | `identity`, `vulnerability` | This Relationship documents that this Tool is being used to target this Identity or exploit the Vulnerability. For example, a `targets` Relationship linking an exploit Tool to a Vulnerability for CVE-2016-0001 means that the tool exploits that vulnerability. Similarly, a `targets` Relationship linking a DDoS Tool to an Identity representing the energy sector means that Tool is typically used against targets in the energy sector. |

## Vulnerability

> Example:

```json
{
  "type": "vulnerability",
  "id": "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
  "created": "2016-05-12T08:17:27.000Z",
  "modified": "2016-05-12T08:17:27.000Z",
  "name": "CVE-2016-1234",
  "external_references": [
    {
      "source_name": "cve",
      "external_id": "CVE-2016-1234"
    }
  ]
}
```

A Vulnerability is "a mistake in software that can be directly used by a hacker to gain access to a system or network" [CVE]. For example, if a piece of malware exploits CVE-2015-12345, a Malware object could be linked to a Vulnerability object that references CVE-2015-12345.

The Vulnerability SDO is primarily used to link to external definitions of vulnerabilities or to describe 0-day vulnerabilities that do not yet have an external definition. Typically, other SDOs assert relationships to Vulnerability objects when a specific vulnerability is targeted and exploited as part of malicious cyber activity. As such, Vulnerability objects can be used as a linkage to the asset management and compliance process.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `vulnerability`.
| **external_references** (optional) | [list](#list) of type [external-reference](#external-reference) | A list of external references which refer to non-STIX information. This property **MAY** be used to provide one or more Vulnerability identifiers, such as a CVE ID. When specifying a CVE ID, the **source_name** property of the external reference **MUST** be set to cve and the **external_id** property **MUST** be the exact CVE identifier. |
| **name** (required) | [string](#string) | A name used to identify the Vulnerability. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Vulnerability, potentially including its purpose and its key characteristics.

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `attack-pattern`, `campaign`, `intrusion-set`, `malware`, `threat-actor`, `tool` | `targets` | `vulnerability` | This Relationship describes that the Attack Pattern, Campaign, Intrusion Set, Malware, Threat Actor, Tool uses exploits of the related Vulnerability. For example, a `targets` Relationship from the jay-sm17h Threat Actor to a Vulnerability in a blogging platform indicates that attacks performed by John Smith often exploit that Vulnerability. |
| `course-of-action` | `mitigates` | `vulnerability` | This Relationship describes that the Course of Action can mitigate the related Vulnerability. |

## Bundle

> Example:

```json
{
  "type": "bundle",
  "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
      "created": "2016-04-29T14:09:00.000Z",
      "modified": "2016-04-29T14:09:00.000Z",
      "object_marking_refs": ["marking-definition--089a6ecb-cc15-43cc-9494-767639779123"],
      "name": "Poison Ivy Malware",
      "description": "This file is part of Poison Ivy",
      "pattern": "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"
    },
    {
      "type": "marking-definition",
      "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
      "created": "2016-08-01T00:00:00.000Z",
      "definition_type": "tlp",
      "definition": {
        "tlp": "green"
      }
    }
  ]
}
```

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The type property identifies the type of object. The value of this property **MUST** be `bundle`.
| **id** (required) | [identifier](#identifier) | An identifier for this Bundle. The id property for the Bundle is designed to help tools that may need it for processing, but tools are not required to store or track it. Consuming tools should not rely on the presence of this property or the ability to refer to bundles by ID. |
| **spec_version** (required) | [string](#string) | The version of the STIX specification used to represent the content in this Bundle. This enables non-TAXII transports or other transports without their own content identification mechanisms to know the version of STIX content. The value of this property **MUST** be `2.0` for bundles containing STIX Objects defined in this specification.
| **objects** (optional) | [list](#list) of type `<STIX Object or Marking Definition>` | Specifies a set of one or more STIX Objects. Objects in this list **MUST** be a STIX Object (SDO, SRO or Custom Object) or a Marking Definition object. |

### Relationships

Bundle is not a STIX Object and **MUST NOT** have any relationships to it or from it.

## Marking Definition

> Example:

```json
{
  "type": "marking-definition",
  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  "created": "2016-08-01T00:00:00.000Z",
  "definition_type": "foobar-marking",
  "definition": {
    "foo": "bar"
  }
}
```

The marking-definition object represents a specific marking. Data markings typically represent handling or sharing requirements for data, and are applied in the **object_marking_refs** and granular_markings properties on STIX Objects, which reference a list of IDs for `marking-definition` objects.

Two marking definition types are defined in this specification: TLP, to capture TLP markings, and Statement, to capture text marking statements. In addition, it is expected that the FIRST Information Exchange Policy (IEP) will be included in a future version once a machine-usable specification for it has been defined.

Unlike STIX Objects, Marking Definition objects cannot be versioned because it would allow for indirect changes to the markings on a STIX Object. For example, if a Statement marking is changed from "Reuse Allowed" to "Reuse Prohibited", all STIX Objects marked with that Statement marking would effectively have an updated marking without being updated themselves. Instead, a new Statement marking with the new text should be created and the marked objects updated to point to the new marking.

The JSON MTI serialization uses the JSON object type [RFC7159] when representing `marking-definition`.

Name | Type | Description
--------- | ------- | -----------
| **type** (required) | [string](#string) | The type property identifies the type of object. The value of this property **MUST** be `marking-definition`.
| **id** (required) | [identifier](#identifier) | The id property universally and uniquely identifies this Marking Definition. Because the object type is part of the identifier, it is not possible for objects of different types to share the same id.
| **created_by_ref** (optional) | [identifier](#identifier) | The **created_by_ref** property specifies the ID of the identity object that describes the entity that created this Marking Definition. If this attribute is omitted, the source of this information is undefined. This may be used by object creators who wish to remain anonymous.
| **created** (required) | [timestamp](#timestamp) | The created property represents the time at which the Marking Definition was created. The object creator can use the time it deems most appropriate as the time the object was created.
| **external_references** (optional)  | [list](#list) of type [external-reference](#external-reference) | The external_references property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems.
| **object_marking_refs** (optional) | [list](#list) of type [identifier](#identifier) | The **object_marking_refs** property specifies a list of IDs of marking-definitions that apply to this Marking Definition. This property **MUST NOT** contain any references to this Marking Definition object (i.e., it cannot contain any circular references). Though uncommon, in some cases marking definitions themselves may be marked with sharing or handling guidance.
| **granular_markings** (optional) | [list](#list) of type [granular-marking](#granular-marking) | The **granular_markings** property specifies a list of granular markings applied to this. This property **MUST NOT** contain any references to this Marking Definition object (i.e., it cannot contain any circular references). Though uncommon, in some cases Marking Definitions themselves may be marked with sharing or handling guidance.
| **definition_type** (required) | [open-vocab](#open-vocab) | The **definition_type** property identifies the type of Marking Definition. The value of the **definition_type** property **SHOULD** be one of the types defined in the subsections below: statement or tlp (see sections 4.1.3 and 4.1.4)
| **definition** (required) | `<marking-object>` | The definition property contains the marking object itself (e.g., the TLP marking as defined in section 4.1.4, the Statement marking as defined in section 4.1.3, or some other marking definition defined elsewhere).

### Relationships

Data Marking is not a STIX Object and **MUST NOT** have any SRO relationships to it or from it.

### Statement Marking

> Example:

```json
{
  "type": "marking-definition",
  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  "created": "2016-08-01T00:00:00.000Z",
  "definition_type": "statement",
  "definition": {
    "statement": "Copyright 2016, Example Corp"
  }
}
```

The Statement marking type defines the representation of a textual marking statement (e.g., copyright, terms of use, etc.) in a definition. The value of the **definition_type** property **MUST** be `statement` when using this marking type. Statement markings are generally not machine-readable and this specification does not define any behavior or actions based on their values.

Content may be marked with multiple Statement marking types that do not override each other. In other words, the same content can be marked both with a statement saying "Copyright 2016" and a statement saying "Terms of use are ..." and both statements apply.

Name | Type | Description
--------- | ------- | -----------
| **statement** (required) | [string](#string) | A Statement (e.g., copyright, terms of use) applied to the content marked by this marking definition.

### TLP Marking

> TLP:WHITE (always use this ID):

```json
{
  "type": "marking-definition",
  "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "definition": {
    "tlp": "white"
  }
}
```

> TLP:GREEN (always use this ID):

```json
{
  "type": "marking-definition",
  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "definition": {
    "tlp": "green"
  }
}
```

> TLP:AMBER (always use this ID):

```json
{
  "type": "marking-definition",
  "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "definition": {
    "tlp": "amber"
  }
}
```

> TLP:RED (always use this ID):

```json
{
  "type": "marking-definition",
  "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "definition": {
    "tlp": "red"
  }
}
```

The TLP marking type defines how you would represent a Traffic Light Protocol (TLP) marking in a definition property. The value of the **definition_type** property **MUST** be `tlp` when using this marking type.

Because there are only four TLP levels, STIX has pre-defined the STIX objects used to represent them. To use them, reference them by ID directly (see the objects to the right). You could also include the full objects if you want.

### Granular Marking

The `granular-marking` type defines how the `marking-definition` object referenced by the **marking_ref** property applies to a set of content identified by the list of selectors in the selectors property.

Name | Type | Description
--------- | ------- | -----------
| **marking_ref** (required) | [identifier](#identifier) | The marking_ref property specifies the ID of the marking-definition object that describes the marking.
| **selectors** | [list](#list) of type [string](#string) | The selectors property specifies a list of selectors for content contained within the STIX Object in which this property appears. Selectors **MUST** conform to the syntax defined in section 4.3.1.1. The `marking-definition` referenced in the **marking_ref** property is applied to the content selected by the selectors in this list.

#### Selector Syntax

Selectors contained in the selectors list are strings that consist of multiple components that **MUST** be separated by the . character. Each component **MUST** be one of:

* A property name, e.g., description, or;
* A zero-based list index, specified as a non-negative integer in square brackets, e.g., [4]

Selectors denote path traversals: the root of each selector is the STIX Object that the **granular_markings** property appears in. Starting from that root, for each component in the selector, properties and list items are traversed. When the complete list has been traversed, the value of the content is considered selected.

Selectors **MUST** refer to properties or list items that are actually present on the marked object.

> Example of a granular marking:

```json
{
  "id": "vulnerability--ee916c28-c7a4-4d0d-ad56-a8d357f89fef",
  "created": "2016-02-14T00:00:00.000Z",
  "modified": "2016-02-14T00:00:00.000Z",
  "type": "vulnerability",
  "name": "CVE-2014-0160",
  "description": "The (1) TLS...",
  "external_references": [{
    "source_name": "cve",
    "external_id": "CVE-2014-0160"
  }],
  "labels": ["heartbleed", "has-logo"]
}
```

Considering the example to the right, the following selectors are valid:

* `description` selects the **description** property ("The (1) TLS...").
* `external_references.[0].source_name` selects the **source_name** property of the first value of the **external_references** list ("cve").
* `labels.[0]` selects the first item contained within the **labels** list ("heartbleed").
* `labels` selects the list contained in the **labels** property. Due to the recursive nature of the selector, that includes all items in the list (["heartbleed", "has-logo"]).
* `external_references` selects the list contained in the **external_references** property. Due to the recursive nature of the selector, that includes all list items and all properties of those list items.

On the other hand, still looking at the same example, the following selectors are not valid:

* `pattern` and `external_references.[3]` are invalid selectors because they refer to content not present in that object.
* `description.[0]` is an invalid selector because the **description** property is a string and not a list.
* `labels.name` is an invalid selector because **labels** property is a list and not an object.

This syntax is inspired by JSONPath and is in fact a strict subset of allowable JSONPath expressions (with the exception that the '$' to indicate the root is implicit). Care should be taken when passing selectors to JSONPath evaluators to ensure that the root of the query is the individual STIX Object. It is expected, however, that selectors can be easily evaluated in programming languages that implement list and key/value mapping types (dictionaries, hashmaps, etc.) without resorting to an external library.

> Marks the description and labels properties with the single marking definition referenced in the list.

```json
{
  ...
  "granular_markings": [
    {
      "marking_ref": "marking-definition--089a6ecb-cc15-43cc-9494-767639779123",
      "selectors": ["description", "labels"]
    }
  ],
  "description": "Some description",
  "name": "Some name",
  "labels": ["first", "second"]
}
```

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
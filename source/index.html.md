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

Welcome to STIX 2! This documentation is for the STIX 2.0 data model. If you're looking for an introduction or conceptual overview of STIX, see the [documentation](https://cti-tc.github.io).

This documentation is divided into 4 major sections:

* **Objects**: The most important section, start here. It describes the objects used by STIX
* **Common Types**: Reusable types
* **Vocabularies**: The vocabularies (enumerations) used by the core objects

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

The Attack Pattern SDO contains textual descriptions of the pattern along with references to externally-defined taxonomies of attacks such as CAPEC [CAPEC]. Relationships from Attack Pattern can be used to relate it to what it targets (Vulnerabilities and Identities) and which tools and malware use it (Tool and Malware).

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of property field MUST be `attack-pattern`.
| **external_references** (optional) | [list](#list) of type [external-reference](#external-reference) | A list of external references which refer to non-STIX information. This property **MAY** be used to provide one or more Attack Pattern identifiers, such as a CAPEC ID. When specifying a CAPEC ID, the **source_name** property of the external reference **MUST** be set to `capec` and the **external_id** property **MUST** be formatted as CAPEC-[id]. |
| **name** (required) | [string](#string) | A name used to identify the Attack Pattern. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Attack Pattern, potentially including its purpose and its key characteristics. |
| **kill_chain_phases** (optional) | [list](#list) of type [kill-chain-phase](#kill-chain-phase) | The list of Kill Chain Phases for which this Attack Pattern is used.

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `attack-pattern` | `targets` | `identity`, `vulnerability` | This Relationship describes that this Attack Pattern typically targets the type of victims or vulnerability represented by the related Identity or Vulnerability object. For example, a targets Relationship linking an Attack Pattern for SQL injection to an Identity object representing domain administrators means that the form of SQL injection characterized by the Attack Pattern targets domain administrators in order to achieve its objectives. Another example is a Relationship linking an Attack Pattern for SQL injection to a Vulnerability in blogging software means that the particular SQL injection attack exploits that vulnerability.|
| `attack-pattern` | `uses` | `malware`, `tool` | This Relationship describes that the related Malware or Tool is used to perform the behavior identified in the Attack Pattern. For example, a uses Relationship linking an Attack Pattern for a distributed denial of service (DDoS) to a Tool for Low Orbit Ion Cannon (LOIC) indicates that the tool can be used to perform those DDoS attacks. |
| `indicator` | `indicates` | `attack-pattern` | This Relationship describes that the Indicator can detect evidence of the related Attack Pattern. This evidence may not be direct: for example, the Indicator may detect secondary evidence of the Attack Pattern, such as behavioral artifacts commonly associated with it.
| `course-of-action` | `mitigates` | `attack-pattern` | This Relationship describes that the Course of Action can mitigate the related Attack Pattern.
| `campaign`, `intrusion-set`, `threat-actor` | `uses` | `attack-pattern` | This Relationship describes that attacks carried out as part of the Campaign, Intrusion Set, or Threat Actor typically use the related Attack Pattern. For example, a uses Relationship from the Glass Gazelle Campaign to the Spear Phishing Attack Pattern indicates that Spear Phishing is often used during attacks attributed to that Campaign. |

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
| **type** (required) | [string](#string) | The value of property field MUST be `campaign`.
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
| `campaign` | `targets` | `identity`, `vulnerability` | This Relationship describes that the Campaign uses exploits of the related Vulnerability or targets the type of victims described by the related Identity. For example, a targets Relationship from the Glass Gazelle Campaign to a Vulnerability in a blogging platform indicates that attacks performed as part of Glass Gazelle often exploit that Vulnerability. Similarly, a targets Relationship from the Glass Gazelle Campaign to a Identity describing the energy sector in the United States means that the Campaign typically carries out attacks against targets in that sector.
| `campaign `| `uses` | `attack-pattern`, `malware`, `tool` | This Relationship describes that attacks carried out as part of the Campaign typically use the related Attack Pattern, Malware, or Tool. For example, a uses Relationship from the Glass Gazelle Campaign to the xInject Malware indicates that xInject is often used during attacks attributed to that Campaign.
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

**Note: The Course of Action object in STIX 2.0 is a stub. It is included to support basic use cases (such as sharing prose courses of action) but does not support the ability to represent automated courses of action or contain properties to represent metadata about courses of action. Future STIX 2 releases will expand it to include these capabilities.**

A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes. For example, a course of action to mitigate a vulnerability could describe applying the patch that fixes it.

The Course of Action SDO contains a textual description of the action; a reserved action property also serves as placeholder for future inclusion of machine automatable courses of action. Relationships from the Course of Action can be used to link it to the Vulnerabilities or behaviors (Tool, Malware, Attack Pattern) that it mitigates.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of property field MUST be `course-of-action`.
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
| **type** (required) | [string](#string) | The value of property field MUST be `identity`.
| **labels** (required) | [list](#list) of type [string](#string) | The list of roles that this Identity performs (e.g., CEO, Domain Administrators, Doctors, Hospital, or Retailer). No open vocabulary is yet defined for this property.
| **name** (required) | [string](#string) | The name of this Identity. When referring to a specific entity (e.g., an individual or organization), this property **SHOULD** contain the canonical name of the specific entity. |
| **description** (optional) | [string](#string) | A description that provides more details and context about the Identity, potentially including its purpose and its key characteristics. |
| **identity_class** (required) | [open-vocab](#open-vocab) | The type of entity that this Identity describes, e.g., an individual or organization. This is an open vocabulary and the values **SHOULD** come from the [identity-class-ov](#identity-class-ov) vocabulary.
| **sectors** (optional) | [list](#list) of type [open-vocab](#open-vocab) | The list of industry sectors that this Identity belongs to. This is an open vocabulary and values **SHOULD** come from the [industry-sector-ov](#industry-sector-ov) vocabulary. |
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

The Indicator SDO contains a simple textual description, the Kill Chain Phases that it detects behavior in, a time window for when the Indicator is valid or useful, and a required pattern property to capture a structured detection pattern. Conforming STIX implementations MUST support the STIX Patterning Language as defined in STIX™ Version 2.0. Part 5: STIX Patterning. While each structured pattern language has different syntax and potentially different  semantics, in general an Indicator is considered to have "matched" (or been "sighted") when the conditions specified in the structured pattern are satisfied in whatever context they are evaluated in.

Relationships from the Indicator can describe the malicious or suspicious behavior that it directly detects (Malware, Tool, and Attack Pattern) as well as the Campaigns, Intrusion Sets, and Threat Actors that it might indicate the presence of.

Name | Type | Description
--------- | ------- | -----------
| _See [common properties](#common-properties)_
| **type** (required) | [string](#string) | The value of this property **MUST** be `indicator`. |
| **labels** (required) | [list](#list) of type [open-vocab](#open-vocab) | Specifies the type of indicator. This is an open vocabulary and values **SHOULD** come from the [indicator-label-ov](#indicator-label-ov) vocabulary.
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
| **resource_level** (optional) | [open-vocab](#open-vocab) | This defines the organizational level at which this Intrusion Set typically works, which in turn determines the resources available to this Intrusion Set for use in an attack. This is an open vocabulary and values **SHOULD** come from the [attack-resource-level-ov](#attack-resource-level-ov) vocabulary.
| **primary_motivation** (optional) | [open-vocab](#open-vocab) | The primary reason, motivation, or purpose behind this Intrusion Set. The motivation is why the Intrusion Set wishes to achieve the goal (what they are trying to achieve). For example, an Intrusion Set with a goal to disrupt the finance sector in a country might be motivated by ideological hatred of capitalism. This is an open vocabulary and values SHOULD come from the [attack-motivation-ov](#attack-motivation-ov) vocabulary.
| **secondary_motivations** (optional) | [list](#list) of type [open-vocab](#open-vocab) | The secondary reasons, motivations, or purposes behind this Intrusion Set. These motivations can exist as an equal or near-equal cause to the primary motivation. However, it does not replace or necessarily magnify the primary motivation, but it might indicate additional context. This is an open vocabulary and values **SHOULD** come from the [attack-motivation-ov](#attack-motivation-ov) vocabulary.

### Relationships

Source | Name | Target | Description
------ | ---- | ------ | -----------
| _See [common relationships](#common-relationships)_
| `intrusion-set` | `attributed-to` | `threat-actor` | This Relationship describes that the related Threat Actor is involved in carrying out the Intrusion Set. For example, an attributed-to Relationship from the Red Orca Intrusion Set to the Urban Fowl Threat Actor means that the actor carried out or was involved in some of the activity described by the Intrusion Set.


## Malware

## Observed Data

## Relationship

## Report

## Sighting

## Threat Actor

## Tool

## Vulnerability

## Bundle

## Marking Definition

# Vocabularies

## Get All Kittens

# Common Types

## Boolean

A boolean is a value of either true or false. Properties with this type **MUST** have a value of `true` or `false`.

The JSON MTI serialization uses the JSON boolean type [RFC7159], which is a literal (unquoted) true or false.

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

The JSON MTI serialization uses the JSON object type [RFC7159] when representing external-reference.

* In addition to the **source_name** property, at least one of the **description**, **url**, or **external_id** properties **MUST** be present.

Name | Type | Description
--------- | ------- | -----------
| **source_name** (required) | [string](#string) | The source within which the external-reference is defined (system, registry, organization, etc.).
| **description** (optional) | [string](#string) | A human readable description.
| **url** (optional) | [string](#string) | A URL reference to an external resource [RFC3986].
| **hashes** (optional) | [hashes](#hashes) | Specifies a dictionary of hashes for the contents of the url. This SHOULD be provided when the url property is present.
| **external_id** (optional) | [string](#string) | An identifier for the external reference content.

### Float

The float data type represents an IEEE 754 [IEEE 754-2008] double-precision number (e.g., a number with a fractional part). However, because the values ±Infinity and NaN are not representable in JSON, they are not valid values in STIX.

In the JSON MTI serialization, floating point values are represented by the JSON number type [RFC7159].

### Hashes

> A SHA-256 hash with a custom hash"

```json
{
  "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
  "x_foo_hash": "aaaabbbbccccddddeeeeffff0123457890"
}
```

The Hashes type represents 1 or more cryptographic hashes, as a special set of key/value pairs. Accordingly, the name of each hashing algorithm MUST be specified as a key in the dictionary and **MUST** identify the name of the hashing algorithm used to generate the corresponding value. This name **SHOULD** either be one of the values defined in the hash-algorithm-ov OR a custom value prepended with “x_” (e.g., “x_custom_hash”).

Keys **MUST** be unique in each hashes property, **MUST** be in ASCII, and are limited to the characters a-z (lowercase ASCII), A-Z (uppercase ASCII), numerals 0-9, hyphen (`-`), and underscore (`_`). Keys **SHOULD** be no longer than 30 ASCII characters in length, **MUST** have a minimum length of 3 ASCII characters, **MUST** be no longer than 256 ASCII characters in length.

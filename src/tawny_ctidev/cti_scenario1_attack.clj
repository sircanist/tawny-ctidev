(ns tawny-ctidev.cti2-scenario1-att
  (:use [tawny.owl]
        [tawny-ctidev.cti2])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))


(defontology cti2-scenario1-bk
  :iri "https://raw.githubusercontent.com/sircanist/cti-ontology/master/cti_scenario1-bk.owl"
  :prefix "cti2-sc1-bk:"
  :comment "Background knowledge of the possible attacker"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version")

(def honeypot-time (literal "2020-12-31T00:00:00-01:00" :type :XSD_DATE_TIME_STAMP))

(def observed-time (literal "2021-01-01T00:00:00-01:00" :type :XSD_DATE_TIME_STAMP))

(owl-import ctiontology2)
(def ^:macro di #'defindividual)

(di iCompanyXYZ)
(di iBobMayerIdentity)

(di iBobMayerIdentity
    :type Person
    :fact
    (is roles "analyst")
    (is identity_name "BobMayer")
    (is works-for iCompanyXYZ))

(di iCompanyXYZ
    :type Organization
    :fact
    (is created-by iBobMayerIdentity)
    (is identity_name "CompanyXYX"))


(di iImpactAssessment
    :type ImpactAssessment
    ;; (owl-some business-impact None-BusinessImpact)
    :fact
    (is created-by iBobMayerIdentity)
    (is confidence 100)
    (is business-impact Ind-BusinessImpact-None))
(di iIncident
    :type Incident
    :fact
    (is created-by iBobMayerIdentity)
    (is incident-name "Incident1")
    (is incident-status Ind-IncidentStatus-Closed)
    (is discovered-method Ind-DiscoveredMethod-NIDS)
    (is victim iCompanyXYZ)
    (is has-impact iImpactAssessment))

(di iAttackPatternTemplate
    :type AttackPattern
    :fact
    (is created-by iBobMayerIdentity)
    (is stix_id "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736")
    (is attack_pattern_name "PowerShell")
    (is external_references "{\"source_name\": \"mitre-attack\",
                          \"external_id\": \"T1059.001\",
                          \"url\": \"https://attack.mitre.org/techniques/T1059/006\"}"))
(di iAttackPatternDerived
    :type AttackPattern
    :fact
    (is created-by iBobMayerIdentity)
    (is derived-from iAttackPatternTemplate)
    (is attack_pattern_name "Attacker used PowerShell to download malware")
    (is external_references "{\"source_name\": \"mitre-attack\",
                          \"external_id\": \"T1059.001\",
                          \"url\": \"https://attack.mitre.org/techniques/T1059/006\"}"))


(di iIpAttacker
    :type IPv4Address
    :fact
    (is created-by iBobMayerIdentity)
    (is ip_value "1.2.3.4"))

(di iKillChainPhase
    :type KillChainPhase
    :fact
    (is kill_chain_name "lockheed-martin-cyber-kill-chain")
    (is phase_name "exloitation"))

(di iIndicatorPattern
    :type IndicatorPattern-SNORT
    :fact
    (is indicator_pattern_value "alert tcp any any <> 1.2.3.4 any"))


(di iDomainNameAttacker
    :type DomainName
    :fact
    (is created-by iBobMayerIdentity)
    (is domain_name_value "evilattacker.com")
    (is resolves-to iIpAttacker))

(di iObservedDataHoneypot
    :type ObservedData
    :fact
    (is created-by iBobMayerIdentity)
    (is first_observed honeypot-time)
    (is last_observed honeypot-time)
    (is observed-object iDomainNameAttacker)
    (is observed-object iIpAttacker)
    (is number_observed 1))

(di iIndicator
    :type AttributionIndicator CompromisedIndicator MaliciousActivityIndicator
    :fact
    (is created-by iBobMayerIdentity)
    (is indicator-pattern iIndicatorPattern)
    (is kill-chain-phase iKillChainPhase)
    (is indicates iAttackPatternDerived)
    (is based-on iObservedDataHoneypot))

(di iCoA1
    :type CoA
    :fact
    (is created-by iBobMayerIdentity)
    (is coa_description "blocked ip-address 1.2.3.4 by sensor")
    (is coa_name "coA1"),
    (is confidence 100),
    (is coa-cost Ind-CoACost-NONE)
    (is mitigates iAttackPatternDerived)
    (is mitigates iIndicator))

(di iFileHash
    :type MD5_Hash
    :fact
    (is created-by iBobMayerIdentity)
    (is hash-value "1193d996eb185e5457d8caa6c4ef024d"))

(di iFile
    :type File
    :fact
    (is created-by iBobMayerIdentity)
    (is file-hash iFileHash)
    (is file_name "non.exe"))

(di iMalwareInstance
    :type Malware
    :fact
    (is created-by iBobMayerIdentity)
    (is sample iFile))

(di iTool
    :type Tool
    :fact
    (is created-by iBobMayerIdentity)
    (is tool_name "PowerShell")
    (is delivers iMalwareInstance))

(di iObservedDataIncident
    :type ObservedData
    :fact
    (is created-by iBobMayerIdentity)
    (is first_observed observed-time)
    (is last_observed observed-time)
    (is observed-object iDomainNameAttacker)
    (is observed-object iIpAttacker)
    (is observed-object iFile)
    (is number_observed 1))

(di iSightingIncident
    :type Sighting
    :fact
    (is created-by iBobMayerIdentity)
    (is where-sighted iBobMayerIdentity)
    (is where-sighted iCompanyXYZ)
    (is sighting-of iIncident)
    (is first_seen observed-time)
    (is observed-data iObservedDataIncident))

(di iSightingIndicator
    :type Sighting
    :fact
    (is created-by iBobMayerIdentity)
    (is where-sighted iBobMayerIdentity)
    (is where-sighted iCompanyXYZ)
    (is sighting-of iIndicator)
    (is first_seen observed-time)
    (is observed-data iObservedDataIncident))

(di iSightingAttackPattern
    :type Sighting
    :fact
    (is created-by iBobMayerIdentity)
    (is where-sighted iBobMayerIdentity)
    (is where-sighted iCompanyXYZ)
    (is sighting-of iAttackPatternDerived)
    (is first_seen observed-time)
    (is observed-data iObservedDataIncident))


(di iThreatActor
    :type ThreatActor
    :fact
    (is actor_name "HackerGroupXYZ"))

(di iIntrusionSet
    :type IntrusionSet
    :fact
    (is actor_name "attacker-1234")
    (is attributed-to-actor iThreatActor)
    (is targets iCompanyXYZ)
    (is actor-uses iTool)
    (is actor-uses iAttackPatternDerived))


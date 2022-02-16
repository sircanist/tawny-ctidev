(ns tawny-ctidev.cti2-scenario2
  (:use [tawny.owl]
        [tawny-ctidev.cti2])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))


(defontology cti2-scenario2
  :iri "https://raw.githubusercontent.com/sircanist/tawny-ctidev/main/cti2-scenario2.owl"
  :prefix "cti2-sc2:"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version")

(owl-import ctiontology2)

(def honeypot-time (literal "2020-12-31T00:00:00-01:00" :type :XSD_DATE_TIME_STAMP))

(def observed-time (literal "2021-01-01T00:00:00-01:00" :type :XSD_DATE_TIME_STAMP))

(def ^:macro di #'defindividual)

(di iCompanyXYZ)
(di iBobMayerIdentity)

(di iBobMayerIdentity
    :type Person
    :fact
    (is created-by iBobMayerIdentity)
    (is roles "analyst")
    (is identity_name "BobMayer")
    (is works-for iCompanyXYZ))

(di iCompanyXYZ
    :type Organization
    :fact
    (is created-by iBobMayerIdentity)
    (is identity_name "CompanyXYZ"))




(di iIncident
    :type Incident
    (owl-some has-impact (owl-some business-impact BusinessImpact-Major))
    :fact
    (is created-by iBobMayerIdentity)
    (is incident-name "Incident1")
    (is incident-description "adversary hat unauthorised access to vm and tried to drop malware")
    (is discovered-method Ind-DiscoveredMethod-Customer)
    (is victim iCompanyXYZ))


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
    (is attack_pattern_name "Attacker used PowerShell to download malware"))


(di iIpAttacker
    :type IPv4Address
    :fact
    (is created-by iBobMayerIdentity)
    (is ip_value "1.2.3.4"))

(di iKillChainPhase
    :type KillChainPhase
    :fact
    (is created-by iBobMayerIdentity)
    (is kill_chain_name "lockheed-martin-cyber-kill-chain")
    (is phase_name "exloitation"))

(di iIndicatorPattern
    :type IndicatorPattern-SNORT
    :fact
    (is created-by iBobMayerIdentity)
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

(di iSnortsensor
    :type SnortSensor
    :fact
    (is created-by iBobMayerIdentity)
    (is sensor_version "3.210X"))

(di iHoneypotSensor
    :type HoneyPotSensor)

(di iSightingIncident
    :type Sighting
    :fact
    (is created-by iBobMayerIdentity)
    (is where-sighted iBobMayerIdentity)
    (is where-sighted iCompanyXYZ)
    (is sensed-by iSnortsensor)
    (is sensed-by iHoneypotSensor)
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
    (is created-by iBobMayerIdentity)
    (is actor_name "HackerGroupXYZ"))


(di iIntrusionSet
    :type IntrusionSet
    :fact
    (is created-by iBobMayerIdentity)
    (is actor_name "attacker-1234")
    (is attributed-to-actor iThreatActor)
    (is targets iCompanyXYZ)
    (is actor-uses iTool)
    (is actor-uses iAttackPatternDerived))


(di iIncidentGrouping
    :type IncidentGrouping
    :fact
    (is created-by iBobMayerIdentity)
    (is grouping-ref iCompanyXYZ)
    (is grouping-ref iBobMayerIdentity)
    (is grouping-ref iIncident)
    (is grouping-ref iAttackPatternTemplate)
    (is grouping-ref iAttackPatternDerived)
    (is grouping-ref iIpAttacker)
    (is grouping-ref iDomainNameAttacker)
    (is grouping-ref iKillChainPhase)
    (is grouping-ref iIndicatorPattern)
    (is grouping-ref iObservedDataHoneypot)
    (is grouping-ref iIndicator)
    (is grouping-ref iCoA1)
    (is grouping-ref iFileHash)
    (is grouping-ref iFile)
    (is grouping-ref iMalwareInstance)
    (is grouping-ref iTool)
    (is grouping-ref iObservedDataIncident)
    (is grouping-ref iSnortsensor)
    (is grouping-ref iHoneypotSensor)
    (is grouping-ref iSightingIncident)
    (is grouping-ref iSightingIndicator)
    (is grouping-ref iSightingAttackPattern)
    (is grouping-ref iThreatActor)
    (is grouping-ref iIntrusionSet))

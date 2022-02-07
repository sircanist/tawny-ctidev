(ns tawny-ctidev.cti2-scenario1-base
  (:use [tawny.owl]
        [tawny-ctidev.cti2])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))


(defontology cti2-scenario1
  :iri "https://raw.githubusercontent.com/sircanist/ic-owl/dev/owls/cti2-scenario1.owl"
  ;; :iri "https://raw.githubusercontent.com/sircanist/cti-ontology/master/cti2_scenario1.owl"
  :prefix "cti2-sc1:"
  :comment "Scenario1 for the CTI ontology"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version")

(owl-import ctiontology2)

(def honeypot-time (literal "2020-12-31T00:00:00-01:00" :type :XSD_DATE_TIME_STAMP))

(def observed-time (literal "2021-01-01T00:00:00-01:00" :type :XSD_DATE_TIME_STAMP))

(def ^:macro di #'defindividual)

(di iCompanyXYZ)
(di iBobMayerIdentity)

; Sämtliche CTI-Informationen, stammen von dem Analyst \textit{BobMayer}, der für \textit{CompanyXYZ} arbeitet.
(di iBobMayerIdentity
    :type Person
    :fact
    (is roles "analyst")
    (is identity_name "BobMayer")
    (is works-for iCompanyXYZ))

;
; Das Incident ereignet sich in dem Unternehmen \textit{CompanyXYZ}.
(di iCompanyXYZ
    :type Organization
    :fact
    (is created-by iBobMayerIdentity)
    (is identity_name "CompanyXYX"))




; In dem Incident \textit{Incident1} hatte der Threat-Actor unautorisierten Benutzer-Zugriff auf eine VM in der DMZ.
(di iIncident
    :type Incident
    :fact
    (is created-by iBobMayerIdentity)
    (is incident-name "Incident1")
    (is incident-description "adversary hat unauthorised access to vm and tried to drop malware")

    ;; (is confidence Confidence-High)
    ;; (is incident-status Ind-IncidentStatus-Closed)
    (is victim iCompanyXYZ))


; Der Downloads eines Powershell-Scripts wurde durch den Indikator \textit{Indicator1} gesichtet
(di iAttackPatternTemplate
    :type AttackPattern
    :fact
    (is created-by iBobMayerIdentity)
    (is stix_id "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736")
    (is attack_pattern_name "PowerShell")
    (is external_references "{\"source_name\": \"mitre-attack\",
                          \"external_id\": \"T1059.001\",
                          \"url\": \"https://attack.mitre.org/techniques/T1059/006\"}"))

;Der Downloads eines Powershell-Scripts wurde durch den Indikator \textit{Indicator1} gesichtet
(di iAttackPatternDerived
    :type AttackPattern
    :fact
    (is created-by iBobMayerIdentity)
    (is derived-from iAttackPatternTemplate)
    (is attack_pattern_name "Attacker used PowerShell to download malware"))


; Die Beobachtungen der IPv4-Adresse \textit{1.2.3.4} und der Domänenname \textit{evilAttacker.com} waren Basis für den Indikatoren \textit{Indicator1}
(di iIpAttacker
    :type IPv4Address
    :fact
    (is created-by iBobMayerIdentity)
    (is ip_value "1.2.3.4"))

; \textit{Indicator1} deutet auf die Angriffsphase der \textit{Exploitation} hin, einer Phase der \textit{Lockheed-Martin-Cyber-Kill-Chain}.
(di iKillChainPhase
    :type KillChainPhase
    :fact
    (is kill_chain_name "lockheed-martin-cyber-kill-chain")
    (is phase_name "exloitation"))

(di iIndicatorPattern
    :type IndicatorPattern-SNORT
    :fact
    (is indicator_pattern_value "alert tcp any any <> 1.2.3.4 any"))

; Die Beobachtungen der IPv4-Adresse \textit{1.2.3.4} und der Domänenname \textit{evilAttacker.com} waren Basis für den Indikatoren \textit{Indicator1}
(di iDomainNameAttacker
    :type DomainName
    :fact
    (is created-by iBobMayerIdentity)
    (is domain_name_value "evilattacker.com")
    (is resolves-to iIpAttacker))

;der auf den Angreifer hinweist und auf den Beobachtungen des \textit{iHoneypotSensor} aufbaut
(di iObservedDataHoneypot
    :type ObservedData
    :fact
    (is created-by iBobMayerIdentity)
    (is first_observed honeypot-time)
    (is last_observed honeypot-time)
    (is observed-object iDomainNameAttacker)
    (is observed-object iIpAttacker)
    (is number_observed 1))

;Die Beobachtung des Indikators \textit{iIndicator} weißen auf einen Threat-Actor hin.
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
    (is coa-cost Ind-CoACost-NONE) ; Als Gegenmaßnahme (\textit{iCoA1}) wurde die Kommunikation des Angreifers blockiert. Das Ausführen der Gegenmaßnahmen führte zu keinen signifikanten Kosten.
    (is mitigates iAttackPatternDerived)
    (is mitigates iIndicator))

; und die erstellte Datei "non.exe", einer vermeintlichen Schadsoftware.
(di iFileHash
    :type MD5_Hash
    :fact
    (is created-by iBobMayerIdentity)
    (is hash-value "1193d996eb185e5457d8caa6c4ef024d"))

; und die erstellte Datei "non.exe", einer vermeintlichen Schadsoftware.
(di iFile
    :type File
    :fact
    (is created-by iBobMayerIdentity)
    (is file-hash iFileHash)
    (is file_name "non.exe"))

; und die erstellte Datei "non.exe", einer vermeintlichen Schadsoftware.
(di iMalwareInstance
    :type Malware
    :fact
    (is created-by iBobMayerIdentity)
    (is sample iFile))

; Der Downloads eines Powershell-Scripts wurde durch den Indikator \textit{Indicator1} gesichtet
(di iTool
    :type Tool
    :fact
    (is created-by iBobMayerIdentity)
    (is tool_name "PowerShell")
    (is delivers iMalwareInstance))

; Das Incident wurde am 1.1.2020 00:001Z durch die Durchführung des unten beschriebenen Downloads entdeckt.
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

; Die Sensoren \textit{HoneypotSensor} und der \textit{SnortSensor} (in der Version \textit{3.2}) beobachteten das Incident.
(di iSnortsensor
    :type SnortSensor
    :fact
    (is sensor_version "3.210X"))

; Die Sensoren \textit{HoneypotSensor} und der \textit{SnortSensor} (in der Version \textit{3.2}) beobachteten das Incident.
(di iHoneypotSensor
    :type HoneyPotSensor)

; Das Incident wurde am 1.1.2020 00:001Z durch die Durchführung des unten beschriebenen Downloads entdeckt.
(di iSightingIncident
    :type Sighting
    :fact
    (is created-by iBobMayerIdentity)
    (is where-sighted iBobMayerIdentity)
    (is where-sighted iCompanyXYZ) ; Das Incident ereignet sich in dem Unternehmen \textit{CompanyXYZ}.
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
    (is where-sighted iCompanyXYZ) ; Das Incident ereignet sich in dem Unternehmen \textit{CompanyXYZ}.
    (is sighting-of iIndicator)
    (is first_seen observed-time)
    (is observed-data iObservedDataIncident))

(di iSightingAttackPattern
    :type Sighting
    :fact
    (is created-by iBobMayerIdentity)
    (is where-sighted iBobMayerIdentity)
    (is where-sighted iCompanyXYZ) ; Das Incident ereignet sich in dem Unternehmen \textit{CompanyXYZ}.
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
    (is attributed-to-actor iThreatActor) ; Der Threat-Actor wird der Hackergruppe \textit{HackerGroupXYZ} zugeordnet.
    (is targets iCompanyXYZ) ; Das Incident ereignet sich in dem Unternehmen \textit{CompanyXYZ}.
    (is actor-uses iTool)
    (is actor-uses iAttackPatternDerived))

(di iIncidentGrouping
    :type IncidentGrouping
    :fact
    (is grouping-ref iCompanyXYZ) ; Das Incident ereignet sich in dem Unternehmen \textit{CompanyXYZ}.
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

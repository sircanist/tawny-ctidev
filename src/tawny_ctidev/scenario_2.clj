(ns tawny-ctidev.scenario-2
  (:use [tawny.owl]
        [tawny-ctidev.cti])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))

(defontology cti-scenario2
  :iri "http://purl.org/cti-scenario2"
  :prefix "cti-sc2:"
  :comment "Scenario2 for the CTI ontology"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version")

(owl-import ctiontology)

(defn tlp-white [] (is tlp "TLP:WHITE"))
(defn tlp-red [] (is tlp "TLP:RED"))
(def timestamp (literal "2020-10-26T21:32:52" :type :XSD_DATE_TIME))


;;- Indikator basierend auf den Observable
;;- Observable
;;- Incident
;;- Sesnsor
;;- Identity
;;


;; Identity
;; Describes the company that was attacked and analysed the incident
(defindividual CompanyX
  :type CompanyIdentity
  :fact
  (is created timestamp)
  (is externalReference "cti:remote/1234")
  (is shortDescription "This is the test companyX")
  (is title "companyX")
  (tlp-white))

;; Describes the analysier which analysed the incident
(defindividual BobMayerAnalyst
  :type PersonIdentity
  (owl-some hasFeedback NegativeFeedback)
  :fact
  (is created timestamp)
  (is externalReference "cti:remote/1234")
  (is shortDescription "Bob is an analyst")
  (is worksFor CompanyX)
  (is title "Bob Mayer")
  (tlp-white))

;; Describes the source of the incident, which related to the identities which were involved
;; The individual person identity should be kept secret
(defindividual Source1
  :type Source
  :fact
  (is fromIdentity BobMayerAnalyst)
  (is fromIdentity CompanyX)
  (is created timestamp))

;; Describes a different source of the incident, which relates only to the company
(defindividual CompanySource1
  :type Source
  :fact
  (is fromIdentity CompanyX)
  (is created timestamp))

;; Describes the source of the incident, which related to the identities which were involved
;; The individual person identity should be kept secret
(defindividual Source1
  :type Source
  :fact
  (is fromIdentity BobMayerAnalyst)
  (is fromIdentity CompanyX)
  (is created timestamp))

;; Describes the involved hacker group
(defindividual HackerGroupXYZ
  :type HackerGroupIdentity
  :fact
  (is description "The Attacker Group XYZ")
  (is producedBy Source1)
  (is fromSource Source1)
  (is created timestamp))

;; Describes the actor which was involved in the attack, which has an identity of HackerGroup
(defindividual AttackActor
  :type InsiderThreatActor
  (owl-some hasConfidence HighConfidence)
  :fact
  (is description "The indicators indicate that the attacker group was involved")
  (is hasIdentity HackerGroupXYZ)
  (is producedBy Source1)
  (is created timestamp)
  (is fromSource Source1))



;; Describes the involved tool in the attack

(defindividual AttackCampaign
  :type Campaign
  :fact
  (is title "AttackCampaign")
  (is producedBy Source1)
  (is fromSource Source1)
  (is created timestamp))

;; Describes the Observed IP Adress in the attack
(defindividual AttackerIPAddress
  :type IPAtom
  :fact
  (is hasValue "32.12.3.2")
  (is created timestamp)
  (tlp-white)
  (is description "IP of the Attacker")
  (is producedBy Source1)
  (is fromSource Source1))

;; Describes the occurence of the attack sighting
(defindividual AttackerSighting
  :type Sighting
  (owl-some resolvedAs BlockedResolution)
  (owl-some observedBy (owl-and SnortSensor
                                (owl-some sensorVersion (oneof "3.2"))
                                HoneyPotSensor))
  :fact
  (is seenObservable AttackerIPAddress)
  (is producedBy Source1)
  (is created timestamp)
  (is observedTime (literal "2020-10-22T21:32:52" :type :XSD_DATE_TIME))
  (is fromSource Source1))



;; Describes the judgement of the incident which is based on the indicators, the sighting and
;; has a supplied priority, severity and confidence of th correctness
(defindividual IncidentJudgement
  :type Judgement
  (owl-some hasConfidence LowConfidence)
  (owl-some basedOnIndicator SnortIndicator)
  (owl-some hasSeverity HighSeverity)
  (owl-some hasPriority HighPriority)
  (owl-some hasRating EvilRating)
  :fact
  (is basedOnSighting AttackerSighting)
  (is producedBy Source1)
  (is fromSource Source1)
  (is created timestamp))

(defindividual AttackCampaign
  :type Campaign
  :fact
  (is title "AttackCampaign")
  (is producedBy Source1)
  (is fromSource Source1)
  (is created timestamp))


;; Describes information about the incident, which has a confidence in the incident report
;; an effect on the company as well as a takenCourseOfAction (which is described as anonymous in this case)
(defindividual Incident1
  :type ImproperUsageIncident
  (owl-some isDiscoveredBy CustomerDiscovery)
  (owl-some hasConfidence HighConfidence)
  (owl-some hasEffect CompetitionAdvantageEffect)
  (owl-some takenCourseOfAction (owl-and
                                 (owl-some coaCost HighCoaCost)
                                 (owl-some coaEfficacy LowCOAEfficacy)))
  (owl-some hasIncidentState OpenIncidentState)
  :fact
  (is fromCampaign AttackCampaign)
  (is hasSighting AttackerSighting)
  (is producedBy Source1)
  (is discoveredIncidentTime timestamp)
  (is fromSource Source1)
  (is created timestamp))

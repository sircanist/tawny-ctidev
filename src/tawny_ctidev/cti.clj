(ns tawny-ctidev.cti
  (:use [tawny.owl]
        [clojure.tools.trace])
  (:require [clojure.tools.logging :as log]
            [clojure.string :as string]
            [clojure.java.io :as io]
            [clojure.xml :as xml]
            [clojure.zip :as zip]
            [clojure.data.zip.xml :refer [xml-> xml1-> attr text]]
            [tawny-ctidev.utils :as utils]
            [tawny [read] [polyglot] [type] [reasoner :as r] [pattern :as p]]
            )
  (:import
    (org.semanticweb.owlapi.apibinding OWLManager)
    (org.semanticweb.owlapi.profiles Profiles)))


(def current-profile "EL")

(defn get-restriction-of-profile
  ([] (case current-profile
        "EL" owl-some
        "RL" owl-only
        "DL" some-only))

  ;; Because owl-some is bugged for dataproperty workaround is wrap
  ;; it into full owl-and, but therefore property and domain must be supplied
  ([property domain] (case current-profile
                       "EL" (owl-some property domain)
                       "RL" (owl-only property domain)
                       "DL" (owl-and
                             (owl-some property domain)
                             (owl-only property domain)))))

(defontology ctiontology
  :iri "http://purl.org/cti-core"
  :prefix "cti:"
  :comment "An example graph for cyber threat intelligence"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version"
  )


(defmacro mydefoproperty
  [property & {:keys [domain range]}]
  `(do (defoproperty ~property :domain ~domain :range ~range)
       (refine ~domain :super ((get-restriction-of-profile) ~property ~range))))

(defmacro mydefdproperty
  [property & {:keys [domain range]}]
  `(do (defdproperty ~property :domain ~domain :range ~range)
       (refine ~domain :super ((get-restriction-of-profile) ~property ~range))))



;; (defmacro mydefaproperties
;;   [class & properties]
;;   `(map #(mydefaproperty ~class (first %) (rest %)) ~properties))

;; CTIBASE

(defclass CTIBase)

(defmacro defctibase-dp
  [property range]
  `(mydefdproperty ~property
                   :domain CTIBase
                   :range ~range))

(defmacro defctibase-op
  [property range]
  `(mydefoproperty ~property
                  :domain CTIBase
                  :range ~range))


(defctibase-dp created :XSD_DATE_TIME)
(defctibase-dp tlp :XSD_STRING)
(defctibase-dp schemaVersion :XSD_STRING)
(defctibase-dp description :XSD_STRING)
(defctibase-dp externalReference :XSD_STRING)
(defctibase-dp revision :XSD_STRING)
(defctibase-dp shortDescription :XSD_STRING)
(defctibase-dp title :XSD_STRING)


;; Source

(defclass Source
  :super CTIBase)

;; Identity class
(defclass Identity)

;; Source properties
(defmacro defsource-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Source
                  :range ~range))

(defmacro defsource-op
  [property range]
  `(mydefoproperty ~property
                  :domain Source
                  :range ~range))

(defsource-dp sourceName :XSD_STRING)
(defsource-dp sourceURL :XSD_STRING)
(defsource-op fromIdentity Identity)

;; CTIBaseSource Properties
(defclass CTIBaseSource
  :super CTIBase)

(as-disjoint Source
             CTIBaseSource)

(as-disjoint-subclasses
 CTIBaseSource
 (declare-classes AttackEffect
                  Severity
                  CourseOfActionEfficacy
                  SystemRessources
                  Confidence
                  CampaignStatus
                  CampaignActivity
                  Motivation
                  Priority
                  Identity
                  Target
                  Indicator
                  AffectingLikehood
                  Judgement
                  Feedback
                  Location
                  SystemAffecting
                  IncidentDiscovery
                  AffectingConsequence
                  CourseOfActionCost
                  Indicateable
                  Observable
                  Rating
                  CourseOfAction
                  IncidentState
                  Incident
                  Resolution
                  Sensor
                  Sighting))


(defmacro defctibasesource-dp
  [property range]
  `(mydefdproperty ~property
                   :domain CTIBaseSource
                   :range ~range))

(defmacro defctibasesource-op
  [property range]
  `(mydefoproperty ~property
                  :domain CTIBaseSource
                  :range ~range))

(defctibasesource-op fromSource Source)
(defctibasesource-op producedBy Source)

(defctibasesource-op hasFeedback Feedback)

;; 2nd level subclass hyrarchie
;; Indicateable information

(as-disjoint-subclasses
 Indicateable
 (declare-classes Actor
                  Malware
                  Tool
                  Campaign
                  AttackPattern))

(as-subclasses
 SystemAffecting
 (declare-classes Weakness Vulnerable))


;; Facet Properties

(defoproperty hasConfidence
  :range Confidence)

(defoproperty hasIdentity
  :range Identity)

(defoproperty hasSeverity
  :range Severity)

(defoproperty foundAtLocation
  :range Location)

(defoproperty usesMalware
  :range Malware)

(defoproperty usesTool
  :range Tool)

(defoproperty usesAttackPattern
  :range AttackPattern)

(defoproperty hasIntendedAttackEffect
  :range AttackEffect)

(defoproperty attacksTarget
  :range Target)

(defdproperty mitreAttackPhase :range :XSD_STRING)

;; Facets

(defn attacks-facet [class]
  (refine class
          :super ((get-restriction-of-profile) attacksTarget Target)))

(defn confidence-facet [class]
  (refine class
          :super ((get-restriction-of-profile) hasConfidence Confidence)))

(defn identity-facet [class]
  (refine class
          :super ((get-restriction-of-profile) hasIdentity Identity)))

(defn location-facet [class]
  (refine class
          :super ((get-restriction-of-profile) foundAtLocation Location)))

(defn severity-facet [class]
  (refine class
          :super ((get-restriction-of-profile) hasSeverity Severity)))

(defn usesmalware-facet [class]
  (refine class
          :super ((get-restriction-of-profile) usesMalware Malware)))

(defn usestool-facet [class]
  (refine class
          :super ((get-restriction-of-profile) usesTool Tool)))

(defn usesattackpattern-facet [class]
  (refine class
          :super ((get-restriction-of-profile) usesAttackPattern AttackPattern)))

(defn intendedattackeffect-facet [class]
  (refine class
          :super ((get-restriction-of-profile) hasIntendedAttackEffect AttackEffect)))

(defn mitreattackphase-facet [class]
  (refine class
          :super (get-restriction-of-profile mitreAttackPhase :XSD_STRING)))


;; Sensor


(as-subclasses
 Sensor
 (declare-classes
  HoneyPotSensor
  SnortSensor
  FirewallSensor
  AntiVirusSensor
  HumanSensor
  ProxySensor))

(defmacro defsensor-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Sensor
                   :range ~range))

(defmacro defsensor-op
  [property range]
  `(mydefoproperty ~property
                   :domain Sensor
                   :range ~range))

(defsensor-dp sensorVersion :XSD_STRING)

;; Judgement

(defmacro defjudgement-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Judgement
                  :range ~range))

(defmacro defjudgement-op
  [property range]
  `(mydefoproperty ~property
                  :domain Judgement
                  :range ~range))


(confidence-facet Judgement)
(severity-facet Judgement)

(defjudgement-op basedOnIndicator Indicator)
(defjudgement-op basedOnSighting Sighting)
(defjudgement-op hasPriority Priority)
(defjudgement-op hasRating Rating)


;; Sighting


(defmacro defsighting-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Sighting
                   :range ~range))

(defmacro defsighting-op
  [property range]
  `(mydefoproperty ~property
                  :domain Sighting
                  :range ~range))

(severity-facet Sighting)
(confidence-facet Sighting)

(defsighting-op resolvedAs Resolution)
(defsighting-op observedBy Sensor)
(defsighting-op seenObservable Observable)
(defsighting-op observedAt Location)
(defsighting-dp observedTime :XSD_DATE_TIME)

;; Target

(identity-facet Target)

(as-subclasses Target
               (defclassn
                 [IdentityTarget :label "Identity Target" :comment "Target is an Identity"]
                 [ComputerTarget]
                 [NetworkTarget]))
;; AttackEffect

(defmacro defattackeffect-dp
  [property range]
  `(mydefdproperty ~property
                   :domain AttackEffect
                   :range ~range))

(defmacro defattackeffect-op
  [property range]
  `(mydefoproperty ~property
                   :domain AttackEffect
                   :range ~range))

(as-subclasses AttackEffect
               (declare-classes AccountTakeoverEffect
                                CompetitionAdvantageEffect
                                DestructionEffect
                                NoEffect
                                FraudEffect
                                MilitaryEffect
                                TheftEffect))

;; Confidence

(defmacro defconfidence-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Confidence
                   :range ~range))

(defmacro defconfidence-op
  [property range]
  `(mydefoproperty ~property
                  :domain Confidence
                  :range ~range))

(as-disjoint-subclasses Confidence
 (declare-classes HighConfidence
                  LowConfidence
                  MediumConfidence))

;; Severity

(as-disjoint-subclasses Severity
 (declare-classes HighSeverity
                  LowSeverity
                  MediumSeverity))


;; Priority

(defmacro defpriority-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Priority
                  :range ~range))

(defmacro defpriority-op
  [property range]
  `(mydefoproperty ~property
                  :domain Priority
                  :range ~range))

(as-disjoint-subclasses Priority
 (declare-classes HighPriority
                  LowPriority
                  MediumPriority))

;; Motivation

(defmacro defmotivation-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Motivation
                  :range ~range))

(defmacro defmotivation-op
  [property range]
  `(mydefoproperty ~property
                  :domain Motivation
                  :range ~range))

(as-subclasses Motivation
                        (declare-classes EgoMotivation
                                         FinancialMotivation
                                         IdealogicalMotivaiton
                                         MilitaryMotivation
                                         OpportunisticMotivation
                                         PoliticalMotivation))

;; Rating

(defmacro defrating-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Rating
                  :range ~range))

(defmacro defrating-op
  [property range]
  `(mydefoproperty ~property
                  :domain Rating
                  :range ~range))

(as-disjoint-subclasses Rating
                        (declare-classes CleanRating
                                         CommonRating
                                         EvilRating
                                         SuspiciousRating
                                         UnknownRating))

;; Resolution

(defmacro defresolution-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Resolution
                  :range ~range))

(defmacro defresolution-op
  [property range]
  `(mydefoproperty ~property
                  :domain Resolution
                  :range ~range))

(as-disjoint-subclasses Resolution
                        (declare-classes AllowedResolution
                                         BlockedResolution
                                         DetectedResolution
                                         UnknownResolution))

;; Actor

(defmacro defactor-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Actor
                  :range ~range))

(defmacro defactor-op
  [property range]
  `(mydefoproperty ~property
                  :domain Actor
                  :range ~range))

(confidence-facet Actor)
(identity-facet Actor)
(intendedattackeffect-facet Actor)

(defactor-op hasMotivation Motivation)
(defactor-op hasAttackPattern AttackPattern)

(as-subclasses
 Actor
 (declare-classes CustomerActor
                  EcrimeActor
                  HackerActor
                  HacktivistActor
                  InsiderThreatActor
                  StateActor
                  UserActor))

;; Identity

(defmacro defidentity-dp
  [property range]
  `(mydefdproperty ~property
                  :domain Identity
                  :range ~range))

(defmacro defidentity-op
  [property range]
  `(mydefoproperty ~property
                  :domain Identity
                  :range ~range))

(as-subclasses
 Identity
 (declare-classes CompanyIdentity
                  PersonIdentity
                  HackerGroupIdentity))

(mydefoproperty worksFor
                :domain PersonIdentity
                :range CompanyIdentity)

;; Indicator

(as-disjoint-subclasses
 Indicator
 (declare-classes PatternIndicator
                  RuleIndicator
                  ObservableIndicator))

(as-disjoint-subclasses
 RuleIndicator
 (declare-classes SnortIndicator
                  SurricataIndicator
                  OpenIOCIndicator))

(mydefdproperty snortSignature :domain SnortIndicator :range :XSD_STRING)

(defmacro defindicator-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Indicator
                   :range ~range))

(defmacro defindicator-op
  [property range]
  `(mydefoproperty ~property
                  :domain Indicator
                  :range ~range))

(mydefoproperty becauseSeen
                :domain ObservableIndicator
                :range Observable)

(severity-facet Indicator)
(confidence-facet Indicator)
(mitreattackphase-facet Indicator)

(defindicator-dp impactDescription :XSD_STRING)
(defindicator-dp indicatorValue :XSD_STRING)
(defindicator-op indicates Indicateable)

;; Location

(defmacro deflocation-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Location
                   :range ~range))

(defmacro deflocation-op
[property range]
`(mydefoproperty ~property
                 :domain Location
                 :range ~range))

(as-disjoint-subclasses Location
                        (declare-classes ExternalLocation InternalLocation))

(as-disjoint-subclasses Location
                        (declare-classes RealLocation VirtualLocation))


;; Incident

(as-disjoint-subclasses IncidentState
                        (declare-classes NewIncidentState
                                         OpenIncidentState
                                         StalledIncidentState
                                         RejectedIncidentState
                                         ClosedIncidentState
                                         ContainmentAchievedIncidentState
                                         ReportedIncidentState
                                         NoneIncidentState
                                         UnknownIncidentState))


(as-subclasses Incident
               (declare-classes ExerciseIncident
                                UnauthorizedAccessIncident
                                DenialOfServiceIncident
                                MaliciousCodeIncident
                                ImproperUsageIncident
                                ScansIncident
                                InvestigationIncident))


(as-subclasses IncidentDiscovery
               (declare-classes ExternalFraudDetectionDiscovery
                                MonitoringDiscovery
                                LawEnforcementDiscovery
                                CustomerDiscovery
                                UnrelatedPartDiscovery
                                AuditDiscovery
                                AntivirusDiscovery
                                IncidentResponseDiscovery
                                FinancialAuditDiscovery
                                InternalFraudDetectionDiscovery
                                HIPSDiscovery
                                ITAuditDiscovery
                                LogReviewDiscovery
                                NIDSDiscovery
                                SecurityAlwarmDiscovery
                                UserDiscovery
                                UnknownDiscovery))

(defmacro defincident-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Incident
                   :range ~range))

(defmacro defincident-op
[property range]
`(mydefoproperty ~property
                 :domain Incident
                 :range ~range))

(confidence-facet Incident)

(defincident-op hasIncidentState IncidentState)
(defincident-op isDiscoveredBy IncidentDiscovery)
(defincident-op hasEffect AttackEffect)
(defincident-op hasActor Actor)
(defincident-op fromCampaign Campaign)
(defincident-op takenCourseOfAction CourseOfAction)
(defincident-op assignedIdentity Identity)
(defincident-op hasSighting Sighting)
(attacks-facet Incident)

;; TODO TBD exploittarget

(defdproperty discoveredIncidentTime :domain Incident :range :XSD_DATE_TIME )
(defdproperty reportedIncidentTime :domain Incident :range :XSD_DATE_TIME)
(defdproperty remediatedIncidentTime :domain Incident :range :XSD_DATE_TIME)
(defdproperty closedIncidentTime :domain Incident :range :XSD_DATE_TIME)
(defdproperty rejectedIncidentTime :domain Incident :range :XSD_DATE_TIME)

;; CourseOfAction

(defmacro defcoa-dp
[property range]
`(mydefdproperty ~property
                 :domain CourseOfAction
                 :range ~range))

(defmacro defcoa-op
[property range]
`(mydefoproperty ~property
                 :domain CourseOfAction
                 :range ~range))

(as-subclasses
 CourseOfAction
 (declare-classes DiplomaticActionCoA
                  EredicationCoA
                  HardeningCoA
                  InternalBlockingCoA
                  LogicalAccessRestrictionsCoA
                  MonitoringCoA
                  OtherCoA
                  PatchingCoA
                  PerimterBlockingCoA
                  PhysicalAccessRestrictionsCoA
                  PolicyActionsCoA
                  PublicDisclosureCoA
                  RebuildingCoA
                  RedirectionCoA
                  HoneyPotCoA
                  TrainingCoA))


(as-disjoint-subclasses CourseOfActionCost
                        (declare-classes
                         HighCoaCost
                         InfoCOACost
                         LowCOACost
                         MediumCOACost
                         NoneCOACost
                         UnknownCOACost))


(as-disjoint-subclasses CourseOfActionEfficacy
                        (declare-classes
                         HighCOAEfficacy
                         InfoCOAEfficacy
                         LowCOAEfficacy
                         MediumCOAEfficacy
                         NoneCOAEfficacy
                         UnknownCOAEfficacy))

(defcoa-op coaEfficacy CourseOfActionEfficacy)
(defcoa-op coaCost CourseOfActionCost)
(defcoa-dp coaSideEffect :XSD_STRING)


(defcoa-op relatedCourseOfAction CourseOfAction)
(defcoa-op mitigatesAttackPattern AttackPattern)
(defcoa-op mitiagesIncident Incident)
(defcoa-op mitigatesMalware Malware)
(defcoa-op mitiagesTool Tool)




;; Campaign

(defmacro defcampaign-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Campaign
                   :range ~range))

(defmacro defcampaign-op
[property range]
`(mydefoproperty ~property
                 :domain Campaign
                 :range ~range))

(defcampaign-dp campaignType :XSD_STRING)
(defcampaign-op attributedTo Actor)

(confidence-facet Campaign)
(intendedattackeffect-facet Campaign)
(usesmalware-facet Campaign)
(usestool-facet Campaign)
(usesattackpattern-facet Campaign)
(attacks-facet Campaign)


(as-disjoint-subclasses CampaignStatus
                        (declare-classes FutureCampaignStatus
                                         HistoricCampaignStatus
                                         OngoingCampaignStatus))

(mydefdproperty activityTime
                :domain  CampaignActivity
                :range :XSD_DATE_TIME)

(defcampaign-op campaignStatus CampaignStatus)
(defcampaign-op hasActivity CampaignActivity)


;; AttackPattern

(defmacro defattackpatttern-dp
  [property range]
  `(mydefdproperty ~property
                   :domain AttackPattern
                   :range ~range))

(defmacro defattackpatttern-op
  [property range]
  `(mydefoproperty ~property
                   :domain AttackPattern
                   :range ~range))

(usestool-facet AttackPattern)

;; The CAPEC abstraction level for patterns describing techniques to attack a system.
(defattackeffect-dp abstractionLevel :XSD_STRING)

;; The mitre attack phases in JSON
(mitreattackphase-facet AttackPattern)

;; Feedback

(as-subclasses
 Feedback
 (declare-classes PositiveFeedback
                  NegativeFeedback
                  NeutralFeedback))

(defmacro deffeedback-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Feedback
                   :range ~range))

(defmacro deffeedback-op
  [property range]
  `(mydefoproperty ~property
                   :domain Feedback
                   :range ~range))

(deffeedback-dp feedbackReason :XSD_STRING)

;; Kill Chain Phases
;; TODO TBD

;; Observable

(defmacro defobservable-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Observable
                   :range ~range))

(defmacro defobservable-op
  [property range]
  `(mydefoproperty ~property
                   :domain Observable
                   :range ~range))

(defobservable-op hasJudgement Judgement)

(as-disjoint-subclasses
 Observable
 (declare-classes ComplexObservable SimpleObservable) )

(mydefdproperty
 hasValue
 :domain SimpleObservable
 :range :XSD_STRING)

(refine SimpleObservable
        :haskey hasValue)


(as-disjoint-subclasses
 SimpleObservable
 (declare-classes DomainAtom
                  HashAtom
                  IPAtom
                  URLAtom
                  CertificateCommonNameAtom
                  CertificateIssuerAtom
                  CertificateSerialAtom
                  EmailMessageAtom
                  EmailHeaderAtom
                  EmailSubjectAtom
                  FileNameAtom
                  FilePathAtom
                  HostNameAtom
                  ImeiAtom
                  ImsiAtomAtom
                  MacAddressAtom
                  ProcessNameAtom
                  RegistryPathAtom
                  RegistryValueAtom
                  UserAgentAtom
                  UserAtom
                  RegistryKeyAtom
                  ComputerGuidAtom
                  EmailAtom
                  FileAtom))

(as-disjoint-subclasses
 IPAtom
 (declare-classes IPv4Atom IPv6Atom))

(as-disjoint-subclasses
 HashAtom
 (declare-classes SHA256Atom SHA512Atom))

;; Malware

(mitreattackphase-facet Malware)
(mydefdproperty malwareVersion :domain Malware :range :XSD_STRING)

;; Tool

(mydefdproperty toolVersion :domain Tool :range :XSD_STRING)
(mitreattackphase-facet Tool)
(attacks-facet Tool)


;; SystemAffecting

(as-subclasses AffectingConsequence
               (declare-classes AlterExecutionLogicConsequence
                                BypassProtectionMechanismConsequence
                                DenialOfServiceConsequence
                                HideActivitiesConsequence
                                GainPriviligesConsequence
                                ReadFilesConsequence
                                ReadMemoryConsequence
                                ModifyMemoryConsequence
                                ExecuteUnauthorizedCodeConsequence
                                AlterExecutionLogicConsequence))

(as-disjoint-subclasses AffectingLikehood
                        (declare-classes LowAffectingLikeHood
                                         MiddleAffectingLikeHood
                                         HighAffectingLikeHood))

(as-disjoint-subclasses
 SystemRessources
 (declare-classes CPURessource
                  FileRessource
                  MemoryRessource
                  SystemProcessRessource))

(mydefoproperty hasAffectingConsequence
                :domain SystemAffecting
                :range AffectingConsequence)
(mydefoproperty hasAffectingLikehood
                :domain SystemAffecting
                :range AffectingLikehood)
(mydefoproperty hasAffectOnSystemRessource
                :domain SystemAffecting
                :range SystemRessources)

;; Weakness

(defmacro defweakness-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Weakness
                   :range ~range))

(defmacro defweakness-op
  [property range]
  `(mydefoproperty ~property
                   :domain Weakness
                   :range ~range))

(defweakness-op hasSubWeakness Weakness)
(defweakness-op variantOfWeakness Weakness)
(defweakness-op basedOnWeakness Weakness)

;; TODO define modeOfIntroduction and OperatingSystem as class

(defweakness-dp modeOfIntroduction :XSD_STRING)
(defweakness-dp operatingSystem :XSD_STRING)

(defweakness-dp commonWeaknessEnumeration :XSD_STRING)


;; Vulnerable

(defmacro defvulnerable-dp
  [property range]
  `(mydefdproperty ~property
                   :domain Vulnerable
                   :range ~range))

(defmacro defvulnerable-op
  [property range]
  `(mydefoproperty ~property
                   :domain Vulnerable
                   :range ~range))

(defvulnerable-dp commonVulnerableEnumeration :XSD_STRING)

;; =====================================================

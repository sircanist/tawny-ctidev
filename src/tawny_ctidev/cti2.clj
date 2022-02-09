;; TODO 
;; 
;; DiscoveredMethod of Incident and Sighting Sensor - logical axioms possible and not contradicting or refactor
;; Incident was sighted by a method and a incident with sighting of an indicator by a sensor is not contradicting
;; possible refactor would be to attach a Sighting to Incident as Incident was discoveredBy Sighting and add SightingMethod to Sighting > CURRENTLY Sighting > Incident > discoveredMethod

;; Create with priority 1 stix2, 2 stix2 (if needed)
;; Create all common attributes for supertypes
;; Create only required attributes for lower types
;; Add attributes if needed for scenario or competency questions
;;
;; For ENUMS
;; Closed Groups of STRINGS if functional data property should be used
;; Open Group of (distinct subclasses) of a super-class type and object property otherwise
;; Naming - no namespace; if unique just use name; if not use domain- as prefix
;;
;; NOTES
;; Design Patterns http://ontologydesignpatterns.org/registry/navigation.php
;; http://ontologydesignpatterns.org/wiki/Category:ProposedContentOP
(ns tawny-ctidev.cti2
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


(defmacro create-enum                                                                 
  ([super-class enum]
   `(create-enum ~super-class ~enum true))
  ([super-class enum divide?]                                                         
   (let [enum-names (gensym 'enum-names)
         enum-classes (gensym 'enum-classes)]                                             
     `(let [~enum-names (map
                         #(str (.getFragment
                                (.getIRI ~super-class)) "-" %1)
                         ~enum)
            ~enum-classes (map #(p/->Named %1 (owl-class %1)) ~enum-names)]                         
        (do (p/intern-owl-entities ~enum-classes)
            (if ~divide?
              (as-disjoint-subclasses ~super-class (map #(:entity %1) ~enum-classes))      
              (as-subclasses ~super-class (map #(:entity %1) ~enum-classes)))              
            (doall (p/intern-owl-entities (map #(p/->Named (str "Ind-" (:name %1)) (individual (str "ind-" (:name %1)) :label (:name %1) :type (:entity %1))) ~enum-classes)))
            ))))) 


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

(defontology ctiontology2
  ;; :iri "https://raw.githubusercontent.com/sircanist/cti-ontology/master/cti.owl"
  :iri "https://raw.githubusercontent.com/sircanist/tawny-ctidev/main/cti2.owl"
  :prefix "cti2:"
  :comment "An example graph for cyber threat intelligence"
  :versioninfo "Unreleased Version")

(defclass Relationship)

(defmacro mop
  [dorefine? domain property range & other]
  (let [new-class (gensym 'new-class)
        class-name (gensym 'class-name)]
    `(let [~class-name (str "container-" (str '~property))
           ;~new-class (p/->Named ~class-name (owl-class ~class-name))
           ]
       (do
         ;(print ~class-name)
         ;(p/intern-owl-entities (list ~new-class))
         ;(as-subclasses ~new-class (list Relationship ~domain))
         ;(defoproperty ~property :domain (:entity ~new-class) :range ~range ~@other)
            (defoproperty ~property :domain ~domain :range ~range ~@other)
         (when ~dorefine?
           (refine ~domain :super ((get-restriction-of-profile) ~property ~range)))))))

(defmacro mop-no-new-class
  [dorefine? domain property range & other]
  `(do (defoproperty ~property :domain ~domain :range ~range ~@other)
       (when ~dorefine?
         (refine ~domain :super ((get-restriction-of-profile) ~property ~range)))))

(defmacro mdp
  [dorefine? domain property range & other]
  `(do (defdproperty ~property :domain ~domain :range ~range ~@other)
       (when ~dorefine?
         (refine ~domain :super ((get-restriction-of-profile) ~property ~range)))))



;; (defmacro mydefaproperties
;;   [class & properties]
;;   `(map #(mydefaproperty ~class (first %) (rest %)) ~properties))

;; CTIBASE

(defclass StixThing)
(defclass Marking)
(defclass Identity)
(defclass OWLEnum)
(defclass Hash)

(as-disjoint-subclasses
 Hash
 (declare-classes MD5_Hash
                  SHA_1Hash
                  SHA_256Hash
                  SHA_512Hash
                  SHA3_256Hash
                  SHA3_512Hash
                  SSDEEP_Hash
                  TLSH_Hash))

(mdp true Hash hash-value :XSD_STRING :characteristic :functional)

;;;;;;;;;;;;;;;
;; -Identity ;;
;;;;;;;;;;;;;;;
(as-disjoint-subclasses
 Identity
 (declare-classes Person
                  Organization))
(mdp true Identity identity_name :XSD_STRING)
(mdp false Identity contact_information :XSD_STRING)
(mdp false Identity roles :XSD_STRING)
(mop false Person works-for Identity)


(as-disjoint-subclasses
 Marking
 (declare-classes TLPMarking
                  StatementMarking))

(mdp true TLPMarking tlp :XSD_STRING :characteristic :functional)
(mdp true StatementMarking statement :XSD_STRING :characteristic :functional)

(as-disjoint-subclasses
 StixThing
 (declare-classes SDO
                  SRO
                  SCO
                  KillChainPhase))

;; (defclass SDO_SRO)
;; (defclass SCO_SRO)



;; (as-disjoint-subclasses
;;  SDO_SRO_SCO
;;  (declare-classes SDO
;;                   SRO
;;                   SCO
;;                   SDO_SRO
;;                   SRO_SCO))
;; (as-disjoint-subclasses
;;  SDO_SRO
;;  (declare-classes SDO
;;                   SRO))

(defclass Confidence)
(create-enum Confidence
             (list "High"
                   "LowC"
                   "MidC"))

;; type
;; spec_version
;; id
(mop-no-new-class false StixThing confidence Confidence)
(mdp true StixThing stix_id :XSD_STRING)
(mop-no-new-class true StixThing created-by Identity)
(mdp true StixThing created :XSD_DATE_TIME :characteristic :functional)
(mdp true StixThing modified :XSD_DATE_TIME)
(mdp true StixThing labels :XSD_STRING)
(mdp true StixThing revoked :XSD_STRING)
(mdp true StixThing lang :XSD_STRING)
(mdp false StixThing external_references :XSD_STRING)
(mop-no-new-class false StixThing object-marking Marking)
;; granular_markings
;; defanged
;; extensions



(mop false StixThing derived-from StixThing)
(mop false StixThing duplicate-of StixThing
     :characteristic :transitive )
(mop false StixThing related-to StixThing
     :characteristic :transitive )

;;;;;;;;;;;;
;; ;; SDO ;;
;;;;;;;;;;;;

(as-disjoint-subclasses
 SDO
 (declare-classes Incident
                  Identity
                  Grouping
                  ObservedData
                  Indicator
                  ImpactAssessment
                  Opinion
                  Sensor
                  Actor
                  Location
                  Malware
                  Vulnerability
                  Tool
                  AttackPattern
                  Infrastructure
                  CoA
                  ))
(as-disjoint-subclasses
 OWLEnum
 (declare-classes BusinessImpact
                  CIAImpact
                  CoACost
                  Confidence
                  Hash
                  IndicatorPattern
                  IncidentStatus
                  DiscoveredMethod))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; -Relationship Box-Classes ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;  use only for near perfect matches

(defclass Delivering)
(as-subclasses
 Delivering
 (declare-classes AttackPattern
                  Infrastructure
                  Tool))

(defclass Deliverable)
(as-subclasses
 Deliverable
 (declare-classes Malware))

(mop false Delivering delivers Deliverable)

;; Change: Append Infrastructure as well for other types but malware and tool
(defclass Targeting
  (as-subclasses
   (declare-classes AttackPattern
                    Actor
                    Malware
                    Infrastructure
                    Tool)))
(defclass Targetable
  (as-subclasses
   (declare-classes Identity
                    Location
                    Infrastructure
                    Vulnerability)))


(mop false Targeting targets Targetable)


;;;;;;;;;;;;;
;; -Sensor ;;
;;;;;;;;;;;;;
(as-subclasses
 Sensor
 (declare-classes HoneyPotSensor
                  SnortSensor))
(mdp false Sensor sensor_version :XSD_STRING :characteristic :functional)
(mdp true Sensor sensor_name :XSD_STRING :characteristic :functional)
(mdp true Sensor sensor_description :XSD_STRING :characteristic :functional)


;;;;;;;;;;;;;;;
;; -Location ;;
;;;;;;;;;;;;;;;
;; (defclass Locateable
;;   (as-subclasses
;;    (declare-classes Identity
;;                     Infrastructure
;;                     Actor)))
;; (defclass Originateable
;;   (as-subclasses
;;    (declare-classes IntrusionSet
;;                     Malware)))
;; (mop true Locateable located-at Location)
;; (mop true Originateable originates-from Location)


;;;;;;;;;;;;;;;;;;;
;; -ObservedData ;;
;;;;;;;;;;;;;;;;;;;
;; (as-subclasses
;;  SCO_SRO
;;     (declare-classes SCO
;;                   SRO))

(mop true ObservedData observed-object StixThing)
(mdp true ObservedData first_observed :XSD_DATE_TIME_STAMP :characteristic :functional)
(mdp true ObservedData last_observed :XSD_DATE_TIME_STAMP :characteristic :functional)
(mdp true ObservedData number_observed :XSD_NON_NEGATIVE_INTEGER :characteristic :functional)

;;;;;;;;;;;;;;;;;;;;;
;; -Infrastructure ;;
;;;;;;;;;;;;;;;;;;;;;
(defclass Communicateable)
(as-subclasses
 Communicateable
 (declare-classes Infrastructure
                  IPAddress
                  DomainName))
(defclass Consistable)
(as-subclasses
 Consistable
 (declare-classes Infrastructure
                  ObservedData
                  SCO))
(defclass Controllable)
(as-subclasses
 Controllable
 (declare-classes Infrastructure
                  Malware))
(defclass Hostable)
(as-subclasses
 Hostable
 (declare-classes Tool
                  Malware))
(as-subclasses
 Infrastructure
 (declare-classes AssetInfrastructure
                  AttackerInfrastructure))
(as-subclasses
 AttackerInfrastructure
 (declare-classes AmplificationAttackerInfrastructure
                  AnonymizationAttackerInfrastructure
                  BotnetAttackerInfrastructure
                  CommandAndControlAttackerInfrastructure
                  ExfiltrationAttackerInfrastructure
                  HostingMalwareAttackerInfrastructure
                  HostingTargetListAttackerInfrastructure
                  PishingAttackerInfrastructure
                  ReceissanceAttackerInfrastructure
                  StagingAttackerInfrastructure
                  UnknownAttackerInfrastructure))
;; merged STIX1 Asset types to describe defensive Structures
(as-subclasses
 AssetInfrastructure
 (declare-classes  BackupAssetInfrastructure
                   DatabaseAssetInfrastructure
                   DHCPAssetInfrastructure
                   DirectoryAssetInfrastructure
                   DCSAssetInfrastructure
                   DNSAssetInfrastructure
                   FileAssetInfrastructure
                   LogAssetInfrastructure
                   MailAssetInfrastructure
                   MainframeAssetInfrastructure
                   PaymentswitchAssetInfrastructure
                   POScontrollerAssetInfrastructure
                   PrintAssetInfrastructure
                   ProxyAssetInfrastructure
                   RemoteaccessAssetInfrastructure
                   SCADAAssetInfrastructure
                   WebapplicationAssea
                   ServerAssetInfrastructure
                   AccessreaderAssetInfrastructure
                   CameraAssetInfrastructure
                   FirewallAssetInfrastructure
                   HSMAssetInfrastructure
                   IDSAssetInfrastructure
                   BroadbandAssetInfrastructure
                   PBXAssetInfrastructure
                   PrivateWANAssetInfrastructure
                   PLCAssetInfrastructure
                   PublicWANAssetInfrastructure
                   RTUAssetInfrastructure
                   RouterorswitchAssetInfrastructure
                   SANAssetInfrastructure
                   TelephoneAssetInfrastructure
                   VoIPadapterAssetInfrastructure
                   LANAssetInfrastructure
                   WLANAssetInfrastructure
                   NetworkAssetInfrastructure
                   AuthtokenAssetInfrastructure
                   ATMAssetInfrastructure
                   DesktopAssetInfrastructure
                   PEDpadAssetInfrastructure
                   GasterminalAssetInfrastructure
                   LaptopAssetInfrastructure
                   MediaAssetInfrastructure
                   MobilephoneAssetInfrastructure
                   PeripheralAssetInfrastructure
                   POSterminalAssetInfrastructure
                   KioskAssetInfrastructure
                   TabletAssetInfrastructure
                   VoIPphoneAssetInfrastructure
                   UserDeviceAssetInfrastructure
                   TapesAssetInfrastructure
                   DiskmediaAssetInfrastructure
                   DocumentsAssetInfrastructure
                   FlashdriveAssetInfrastructure
                   DiskdriveAssetInfrastructure
                   SmartcardAssetInfrastructure
                   PaymentcardAssetInfrastructure
                   AdministratorAssetInfrastructure
                   AuditorAssetInfrastructure
                   CallcenterAssetInfrastructure
                   CashierAssetInfrastructure
                   CustomerAssetInfrastructure
                   DeveloperAssetInfrastructure
                   End-userAssetInfrastructure
                   ExecutiveAssetInfrastructure
                   FinanceAssetInfrastructure
                   FormeremployeeAssetInfrastructure
                   GuardAssetInfrastructure
                   HelpdeskAssetInfrastructure
                   HumanresourcesAssetInfrastructure
                   MaintenanceAssetInfrastructure
                   ManagerAssetInfrastructure
                   PartnerAssetInfrastructure
                   PersonAssetInfrastructure
                   UnknownAssetInfrastructure
))
(mop false Infrastructure infrastructure-uses Infrastructure)
(mop false Infrastructure infrastructure-hosts Hostable)
(mop false Infrastructure infrastructure-has-vuln Vulnerability)
(mop false Infrastructure infrastructure-controls Controllable)
(mop false Infrastructure infrastructure-consists-of Consistable)
(mop false Infrastructure infrastructure-communicates-with Communicateable)
(mdp true Infrastructure infrastructure_name :XSD_STRING)

;;;;;;;;;;;
;; -Tool ;;
;;;;;;;;;;;
(mop false Tool tool-delivers Malware)
(mop false Tool tool-delivers Malware)
(mdp true Tool tool_name :XSD_STRING)

;;;;;;;;;;
;; -CoA ;;
;;;;;;;;;;
;; Create Enum because multiple coaCost could make sense (in case of updates)
(as-subclasses
 CoA
 (declare-classes PatchCoA))
(defclass Mitigateable)
(as-subclasses
 Mitigateable
 (declare-classes AttackPattern
                  Indicator
                  Malware
                  Tool
                  Vulnerability))
(create-enum CoACost (list "HIGH" "MEDIUM" "LOW" "NONE"))
(mop false CoA coa-cost CoACost)
(mop false CoA mitigates Mitigateable)
(mop false CoA coa-applied-by Identity)
(mop false CoA investigates Indicator )
(mdp true CoA coa_name :XSD_STRING)
(mdp true CoA coa_description :XSD_STRING)

;;;;;;;;;;;;;;;;
;; -Indicator ;;
;;;;;;;;;;;;;;;;
(defclass Indicateable)
(as-subclasses
 Indicateable
 (declare-classes AttackPattern
                  Infrastructure
                  Malware
                  Actor
                  Tool))
(create-enum IndicatorPattern (list "stix"
                   "PCRE"
                   "SIGMA"
                   "SNORT"
                   "SURICATA"
                   "YARA") true)
(as-subclasses
 Indicator
 (declare-classes AttributionIndicator
                  CompromisedIndicator
                  UnknownIndicator
                  BenignIndicator
                  AnonymizationIndicator
                  AnomalousActivityIndicator
                  MaliciousActivityIndicator))
(mop true Indicator indicates Indicateable)
(mop true Indicator indicator-pattern IndicatorPattern)
(mop false Indicator based-on ObservedData)
(mop false Indicator kill-chain-phase KillChainPhase)
(mdp false Indicator indicator_valid_from :XSD_DATE_TIME)
(mdp true IndicatorPattern indicator_pattern_value :XSD_STRING)

;;;;;;;;;;;;;;
;; -Malware ;;
;;;;;;;;;;;;;;
(as-disjoint-subclasses
 Malware
 (declare-classes MalwareInstance
                  MalwareFamily))
(defclass Communicateable)
(as-subclasses
 Communicateable
 (declare-classes IPAddress
                  DomainName))
(defclass MalwareDownloadable)
(as-subclasses
 MalwareDownloadable
 (declare-classes Malware
                  Tool
                  Software
                  File))
(defclass MalwareUseable)
(as-subclasses
 MalwareUseable
 (declare-classes AttackPattern
                  Infrastructure
                  Malware
                  Tool))
(mop false Malware beacons-to Infrastructure)
(mop false Malware exfiltrate-to Infrastructure)
(mop false Malware communicates-with Communicateable)
(mop false Malware controls Malware)
(mop false Malware downloads MalwareDownloadable)
(mop false Malware malware-drops MalwareDownloadable)
(mop false Malware exploits Vulnerability)
(mop false Malware malware-uses MalwareUseable)
(mop false Malware variant-of Malware)
(mop false Malware sample File)



;; (mdp true Malware is_familiy (oneof "yes" "no"))

;;;;;;;;;;;;
;; -Asset ;; outdated now using the Infrastructure Asset Subtypes
;;;;;;;;;;;;
;; (mdp true Asset asset_description :XSD_STRING)
;; ;; create ENUM because asset_type must not be functional
;; (mop true Asset asset-type AssetType)
;; (create-enum AssetType (list
;;                             "Backup"
;;                             "Database"
;;                             "DHCP"
;;                             "Directory"
;;                             "DCS"
;;                             "DNS"
;;                             "File"
;;                             "Log"
;;                             "Mail"
;;                             "Mainframe"
;;                             "Paymentswitch"
;;                             "POScontroller"
;;                             "Print"
;;                             "Proxy"
;;                             "Remoteaccess"
;;                             "SCADA"
;;                             "Webapplication"
;;                             "Server"
;;                             "Accessreader"
;;                             "Camera"
;;                             "Firewall"
;;                             "HSM"
;;                             "IDS"
;;                             "Broadband"
;;                             "PBX"
;;                             "PrivateWAN"
;;                             "PLC"
;;                             "PublicWAN"
;;                             "RTU"
;;                             "Routerorswitch"
;;                             "SAN"
;;                             "Telephone"
;;                             "VoIPadapter"
;;                             "LAN"
;;                             "WLAN"
;;                             "Network"
;;                             "Authtoken"
;;                             "ATM"
;;                             "Desktop"
;;                             "PEDpad"
;;                             "Gasterminal"
;;                             "Laptop"
;;                             "Media"
;;                             "Mobilephone"
;;                             "Peripheral"
;;                             "POSterminal"
;;                             "Kiosk"
;;                             "Tablet"
;;                             "VoIPphone"
;;                             "UserDevice"
;;                             "Tapes"
;;                             "Diskmedia"
;;                             "Documents"
;;                             "Flashdrive"
;;                             "Diskdrive"
;;                             "Smartcard"
;;                             "Paymentcard"
;;                             "Administrator"
;;                             "Auditor"
;;                             "Callcenter"
;;                             "Cashier"
;;                             "Customer"
;;                             "Developer"
;;                             "End-user"
;;                             "Executive"
;;                             "Finance"
;;                             "Formeremployee"
;;                             "Guard"
;;                             "Helpdesk"
;;                             "Humanresources"
;;                             "Maintenance"
;;                             "Manager"
;;                             "Partner"
;;                             "Person"
;;                             "Unknown") false)

;;;;;;;;;;;;;;;;;;;;
;; -AttackPattern ;;
;;;;;;;;;;;;;;;;;;;;
(mdp true AttackPattern attack_pattern_name :XSD_STRING)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; -Actor -ThreatActor -IntrusionSet ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(as-subclasses
 Actor
 (declare-classes ThreatActor
                  IntrusionSet))
(defclass ActorUsable)
(as-subclasses
 ActorUsable
 (declare-classes AttackPattern
                  Infrastructure
                  Tool
                  Malware))
(mop false ThreatActor attributed-to-identity Identity)
(mop false IntrusionSet attributed-to-actor Actor)
(mop false Actor impersonates Identity)
(mop false Actor actor-hosts Infrastructure)
(mop false Actor actor-uses ActorUsable)
(mop false Actor owns Infrastructure)
(mop false Actor compromises Infrastructure)
(mdp true Actor actor_name :XSD_STRING)

;;;;;;;;;;;;;;;;;
;;  -Incident  ;;
;;;;;;;;;;;;;;;;;

(mop true Incident has-impact ImpactAssessment)
(create-enum
 IncidentStatus
 (list "New" "Open" "Stalled" "ContainmentAchived" "RestorationAchived"
  "IncidentReported" "Closed" "Rejected" "Deleted"))
(mop true Incident incident-status IncidentStatus)
(mop true Incident victim Identity)
(mop true Incident responder Identity)
(mop true Incident reporter Identity)
(mop true Incident coordinator Identity)

(create-enum
 DiscoveredMethod
 (list "AgentDisclosure",
   "ExternalFraudDetection",
   "MonitoringService",
   "Customer",
   "UnrelatedParty",
   "Audit",
   "Antivirus",
   "IncidentResponse",
   "FinancialAudit",
   "InternalFraudDetection",
   "HIPS",
   "ITAudit",
   "LogReview",
   "NIDS",
   "SecurityAlarm",
   "User",
   "Unknown") false)
(mop true Incident discovered-method DiscoveredMethod)
(mdp true Incident incident-description :XSD_STRING)
(mdp true Incident incident-name :XSD_STRING)

;;;;;;;;;;;;;;;;;;;;;;
;;-ImpactAssessment ;;
;;;;;;;;;;;;;;;;;;;;;;
(create-enum
 BusinessImpact
 (list "None" "Minor" "Moderate" "Major" "Unknown"))
(create-enum
 CIAImpact
 (list "Condidentiality" "Integrity" "Availability") false)
(mop false ImpactAssessment business-impact BusinessImpact)
(mop false ImpactAssessment cia-impact CIAImpact)
(mop false ImpactAssessment affected-asset AssetInfrastructure)


;;;;;;;;;;;;;;;;;;;;
;; -Vulnerability ;;
;;;;;;;;;;;;;;;;;;;;

(defclass CVSS
  :subclass OWLEnum)
(create-enum
 CVSS (list "None"
            "Low"
            "Medium"
            "High"
            "Critical"))

(mop false Vulnerability cvss CVSS)
(mdp false Vulnerability vuln_is_known :XSD_INTEGER :characteristic :functional)
(mdp false Vulnerability vuln_name :XSD_STRING)
(mdp false Vulnerability vuln_description :XSD_STRING)
(mdp false Vulnerability cve :XSD_STRING)
;; (mdp false Vulnerability vuln-discovered :XSD_DATE_TIME_STAMP)
;; (mdp false Vulnerability vuln-published :XSD_DATE_TIME_STAMP)


;;;;;;;;;;;;;;;;;;;;;;;
;; -Opinion -Feedbak ;;
;;;;;;;;;;;;;;;;;;;;;;;

(as-disjoint-subclasses
 Opinion
 (declare-classes
  ;; StronglyDisagreeOpinion
  DisagreeOpinion
  NeutralOpinion
  AgreeOpinion
  ;; StronglyAgreeOpinion
  ))

(defclass StronglyDisagreeOpinion
        :super DisagreeOpinion)
(defclass StronglyAgreeOpinion
        :super AgreeOpinion)
(mop true Opinion opinion-author Identity)
(mop true Opinion opinion-on StixThing)
(mdp true Opinion opinion-explanation :XSD_STRING)

;;;;;;;;;;;;;;;
;; -Grouping ;;
;;;;;;;;;;;;;;;

;; used to group incident elements together

(as-disjoint-subclasses
 Grouping
 (declare-classes IncidentGrouping
                  SuspiciousActivityGrouping
                  MalwareAnalysisGrouping))

(mop true Grouping grouping-ref StixThing)

;;;;;;;;;;
;; -SRO ;;
;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;
;; ;; -Relationships ;;
;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NOTE DEPRECATED! - see new one below                                                                                             ;;
;; ;;                                                                                                                               ;;
;; ;; could be reified, but introduces a maintance problem, http://ontogenesis.knowledgeblog.org/993/                               ;;
;; ;; like this SDO_SCO_SRO > relates-to > relationship (object), which has relationship-target > target                            ;;
;; ;; create a property for domain and range a relationship is_type and use it on individual as an r-filler or as a property        ;;
;; ;; subclassof is_type (self)                                                                                                     ;;
;; ;; create a property chain so that i.e.: relates-to \circ \is_IndicatesRelation \circ \target -> indicates                       ;;
;; ;;                                  or : relates-to \circ \target -> relates-to (property superclass for all SDO / SCO relations ;;
;; ;; see http://ontologydesignpatterns.org/wiki/Submissions:N-Ary_Relation_Pattern_%28OWL_2%29                                     ;;
;;                                                                                                                                  ;;
;; ;; currently relationships could be used, but serve no semantic meaning                                                          ;;
;;                                                                                                                                  ;;
;; ;; added semantic according to design pattern http://ontologydesignpatterns.org/wiki/Submissions:N-Ary_Relation_Pattern_(OWL_2)  ;;
;; ;; but only for relationship, reading the meta-values are not transferred                                                        ;;
;; ;; that results in new properties for is_a_property for each property of stixthings                                              ;;
;; ;; and additional subclass property axioms                                                                                       ;;
;;                                                                                                                                  ;;
;; ;; they are defined at the bottom                                                                                                ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;
;; 


(as-disjoint-subclasses
 SRO
 (declare-classes Relationship
                  Sighting))
;; for each StixThing add a target to relationship, so no inverse properties are needed (defined at the bottom, see -is-a -PropertyChains)
;; (mdp true Relationship relationship_type :XSD_STRING)
;; (mop true Relationship relationship-source SDO_SRO)
;; (defoproperty relationship-target :domain Relationship)
                                        ; do not include range, because of global restrictions
;; (mop true Relationship relationship-target SDO_SRO)

;;;;;;;;;;;;;;;
;; -Sighting ;;
;;;;;;;;;;;;;;;
(mop true Sighting sighting-of SDO)
(mop true Sighting observed-data ObservedData)
(mop true Sighting where-sighted Identity)
(mop true Sighting sensed-by Sensor)
(mdp true Sighting first_seen :XSD_DATE_TIME_STAMP :characteristic :functional)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; -IPAddress -IPv4Addres -IPv6Address ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(as-disjoint-subclasses
 SCO
 (declare-classes IPAddress
                  DomainName
                  File))

;;;;;;;;;;
;; -SCO ;;
;;;;;;;;;;

;;;;;;;;;;;
;; -File ;;
;;;;;;;;;;;
(mop false File file-hash Hash)
(mdp false File file_name :XSD_STRING)

;;;;;;;;;;;;;;;
;; -Software ;;
;;;;;;;;;;;;;;;
(mdp false Software cpe :XSD_STRING)
(mdp false Software software-name :XSD_STRING)

;;;;;;;;;;;;;;;;
;; -IPAddress ;;
;;;;;;;;;;;;;;;;
(mdp true IPAddress ip_value :XSD_STRING)

;;;;;;;;;;;;;
;; -Domain ;;
;;;;;;;;;;;;;
(mop false DomainName resolves-to IPAddress)
(mdp true DomainName domain_name_value :XSD_STRING)

(as-disjoint-subclasses
 IPAddress
 (declare-classes IPv4Address
                  IPv6Address))


;;;;;;;;;;;;;;;;
;; -KillChain ;;
;;;;;;;;;;;;;;;;
(mdp true KillChainPhase kill_chain_name :XSD_STRING :characteristic :functional)
(mdp true KillChainPhase phase_name :XSD_STRING :characteristic :functional)


(defn check-ontology []
  (if (and (r/consistent?) (r/coherent?))
    "coherent and consistent"
    "!!!!!!!!!!!!!!FIX NEEEDED ERROR!!!!!!!!!!!!!!"))

(defn create-test-instances []
  (p/intern-owl-entities (map (fn [clas]
                (let [name (str "ind-" (.getFragment (.getIRI clas)))]
                  (do (print name)
                      (p/->Named name (individual name :type clas))))) (r/isubclasses (owl-thing)))))



;;;;;;;;;;;;;;;;;;;;;;;;;;
;; -PropertyChains -isA ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;

;; this must be executed for all new stixthing properties, because reasoner cannot do this
;; automatically atm

;; add new-properties to the call of the macro below


(defmacro create-relationship-is-a
  ([property-list]                                                         
   (let [property-names (gensym 'property-names)
         property-classes (gensym 'property-classes)
         property-targets (gensym 'property-target)]
     `(let [~property-names (map
                             #(str "is-a-" (.getFragment
                                            (.getIRI %1)))
                             ~property-list)
            ~property-targets (map
                             #(str (.getFragment
                                            (.getIRI %1)) "-target")
                         ~property-list)
            ~property-classes (map #(p/->Named %1 (object-property %1 :domain Relationship :range Relationship)) ~property-names)
            ~property-targets (map (fn [~'target ~'prop-name]
                                     (p/->Named ~'target (object-property ~'target
                                                                        :domain Relationship
                                                                        :range (first
                                                                                (map #(.getRange %1)
                                                                                        (.getObjectPropertyRangeAxioms ctiontology2 ~'prop-name)))))) ~property-targets ~property-list)
            ]                         
        (do (p/intern-owl-entities ~property-classes)
            (p/intern-owl-entities ~property-targets)
            ;; (doall (map #(print %1) ~property-classes))
            ;; (doall (map (#(refine (:entity %1) :subchain [(:entity %2) relationship-target])) ~property-list ~property-classes))
                (doall (map #(refine %1 :subchain [has-relationship (:entity %2) %3]) ~property-list ~property-classes ~property-targets))
            ))))) 

(mop false StixThing has-relationship Relationship)

(create-relationship-is-a (list actor-hosts
                                actor-uses
                                affected-asset
                                attributed-to-actor
                                attributed-to-identity
                                based-on
                                beacons-to
                                business-impact
                                cia-impact
                                coa-applied-by
                                coa-cost
                                communicates-with
                                compromises
                                confidence
                                coordinator
                                delivers
                                ;; derived-from
                                downloads
                                ;; duplicate-of
                                exfiltrate-to
                                exploits
                                file-hash
                                ;; grouping-refs
                                file-hash
                                has-impact
                                ;; has-relationship
                                impersonates
                                incident-status
                                indicates
                                ;; indicator-pattern
                                infrastructure-communicates-with
                                infrastructure-consists-of
                                infrastructure-controls
                                infrastructure-has-vuln
                                infrastructure-hosts
                                infrastructure-uses
                                investigates
                                kill-chain-phase
                                ;; located-at
                                malware-drops
                                malware-uses
                                mitigates
                                ;; object-marking
                                observed-data
                                observed-object
                                opinion-author
                                opinion-on
                                ;; originates-from
                                owns
                                related-to
                                ;; relationship-target
                                reporter
                                resolves-to
                                responder
                                sample
                                sensed-by
                                sighting-of
                                targets
                                tool-delivers
                                variant-of
                                victim
                                where-sighted))


;; TEST
;; 
;; (defn test-with-new-inviduals []
;;   (do
;;     (create-test-instances)
;;     (check-ontology)))
;;
;; subproperty chain
;; (defoproperty blub :subchain [delivers confidence])


(ns tawny-ctidev.cti2-scenario2-policy
  (:use [tawny.owl]
        [tawny-ctidev.cti2]
        [tawny-ctidev.cti2-scenario2]
        [tawny-ctidev.cti2-scenario2-bk])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))

;;;;;;;;;;;;;;;;;;;;
;; SENSITIVE DATA ;;
;;;;;;;;;;;;;;;;;;;;

(defontology cti2-scenario2-policy
  ;; :iri "https://raw.githubusercontent.com/sircanist/cti-ontology/master/cti2_scenario2-sensitive.owl"
  :iri "https://raw.githubusercontent.com/sircanist/ic-owl/dev/owls/cti2_scenario2-policy.owl"
  :prefix "cti2-sc2-policy:"
  :comment "Policy describing the sensitive data of the incident"
  :versioninfo "Unreleased Version")



;; (defclass CompanyIdentified1_sub
;;   :equivalent
;;   (owl-and IncidentGrouping
;;            (owl-some grouping-ref (owl-and Identity
;;                                            (has-value works-for CompanyX))))
;;   :subclass CompanyIdentified)


(di P1_1
    :type
    (owl-and BK_CompanyXVictim
             IncidentGrouping
             (owl-some grouping-ref (owl-some business-impact BusinessImpact-Major))))

(di P1_2
    :type
    (owl-and BK_CompanyXVictim
             IncidentGrouping
             (owl-some grouping-ref (owl-and ImpactAssessment
                                                 (owl-some business-impact BusinessImpact-Major)))))

(di P1_3
    :type
    (owl-and BK_CompanyXVictim
             IncidentGrouping
             (owl-some grouping-ref (owl-and Incident
                                             (owl-some has-impact
                                                       (owl-some business-impact BusinessImpact-Major))))))

(di P2_1
    :type
    (owl-and BK_CompanyXVictim
             IncidentGrouping
             (owl-some grouping-ref (owl-and Incident
                                                 (owl-some discovered-method DiscoveredMethod-Customer)))))

(di P2_2
    :type
    (owl-and BK_CompanyXVictim
             IncidentGrouping
             (owl-some grouping-ref (owl-some discovered-method DiscoveredMethod-Customer))))
(di P2_3
    :type
    (owl-and BK_CompanyXVictim
             IncidentGrouping
             (owl-some grouping-ref DiscoveredMethod-Customer)))

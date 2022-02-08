(ns tawny-ctidev.cti2-scenario1-policy
  (:use [tawny.owl]
        [tawny-ctidev.cti2]
        [tawny-ctidev.cti2-scenario1]
        [tawny-ctidev.cti2-scenario1-bk])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))

;;;;;;;;;;;;;;;;;;;;
;; SENSITIVE DATA ;;
;;;;;;;;;;;;;;;;;;;;

(defontology cti2-scenario1-policy
  ;; :iri "https://raw.githubusercontent.com/sircanist/cti-ontology/master/cti2_scenario1-sensitive.owl"
  :iri "https://raw.githubusercontent.com/sircanist/tawny-ctidev/main/cti2-scenario1-policy.owl"
  :prefix "cti2-sc1-policy:"
  :comment "Policy describing the sensitive data of the incident"
  :versioninfo "Unreleased Version")


(defindividual P1
  :type
  (owl-and IncidentGrouping
           (owl-some grouping-ref
                     (owl-and Sighting
                              (owl-some sighting-of Incident)
                              (owl-some sensed-by BK1_AttackableSensor)))))

(defindividual P2_1
  :type BK2_HoneyPotSystem1)

(defindividual P2_2
  :type BK2_HoneyPotSystem2)

(defindividual P2_3
  :type BK2_HoneyPotSystem3)

(defindividual P3
  :type BK3_AttackerInCTI)

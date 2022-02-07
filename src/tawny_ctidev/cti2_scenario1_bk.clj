(ns tawny-ctidev.cti2-scenario1-bk
  (:use [tawny.owl]
        [tawny-ctidev.cti2]
        [tawny-ctidev.cti2-scenario1])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BACKGROUND KNOWLEDGE OF THE ATTACKER ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defontology cti2-scenario1-bk
  :iri "https://raw.githubusercontent.com/sircanist/ic-owl/dev/owls/cti2-scenario1-bk.owl"
  ;; :iri "https://raw.githubusercontent.com/sircanist/cti-ontology/master/cti2_scenario1-bk.owl"
  :prefix "cti2-sc1-bk:"
  :comment "Background knowledge of the possible attacker"
  :versioninfo "Unreleased Version")


(defclass BK1_AttackableSensor
  :equivalent
  (owl-and SnortSensor
           (has-value sensor_version "3.210X")))


(defclass BK2_HoneyPotSystem1
  :equivalent
  (owl-and
   IncidentGrouping
   (owl-some grouping-ref
             HoneyPotSensor)))


(defclass BK2_HoneyPotSystem2
  :equivalent
  (owl-and
   IncidentGrouping
   (owl-some grouping-ref
             (owl-some has-relationship
                       (owl-and (owl-some business-impact-target BusinessImpact-None)
                                (owl-some confidence Confidence-High)))
             (owl-some has-relationship
                       (owl-and (owl-some incident-status-target IncidentStatus-Closed)
                                (owl-some confidence Confidence-High))))))

(defclass BK2_HoneyPotSystem3
  :equivalent
  (owl-and
   IncidentGrouping
   (owl-some grouping-ref
             (owl-and (owl-some business-impact-target BusinessImpact-None)
                      (owl-some confidence Confidence-High)))
   (owl-some grouping-ref
                (owl-and (owl-some incident-status-target IncidentStatus-Closed)
                      (owl-some confidence Confidence-High)))))

(defclass BK3_AttackerInCTI
  :equivalent
  (owl-and
   IncidentGrouping
   (owl-some grouping-ref (owl-and Actor
                                   (has-value actor_name "HackerGroupXYZ")))))


(refine iIncidentGrouping
  :type IncidentGrouping)

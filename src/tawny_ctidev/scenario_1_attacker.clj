(ns tawny-ctidev.scenario-1-attacker
  (:use [tawny.owl]
        [tawny-ctidev.cti])
  (:require [tawny-ctidev.utils :as utils]
            [tawny-ctidev.scenario-1 :as scenario1])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))

(defontology cti-attacker
  :iri "http://purl.org/cti-scenario1-attacker"
  :prefix "cti-sc1-a:"
  :comment "Scenario1 for the CTI ontology - additional attacker information"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version")


(defclass AttackerAdvantage
  :equivalent
   (owl-some hasConfidence HighConfidence))

(defclass CNCIPAddress)

(refine scenario1/AttackerIPAddress
        :type CNCIPAddress)

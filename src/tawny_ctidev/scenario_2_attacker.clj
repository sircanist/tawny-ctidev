(ns tawny-ctidev.scenario-2-attacker
  (:use [tawny.owl]
        [tawny-ctidev.cti])
  (:require [tawny-ctidev.utils :as utils]
            [tawny-ctidev.scenario-2 :as scenario2])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))

(defontology cti-attacker
  :iri "http://purl.org/cti-scenario2-attacker"
  :prefix "cti-sc2-a:"
  :comment "Scenario1 for the CTI ontology - additional attacker information"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version")


(defclass CompetitorAdvantage
  :equivalent
   (owl-some isDiscoveredBy CustomerDiscovery))


(defclass Competitor)

(defoproperty knownByCompetitor
  :domain CompanyIdentity
  :range Competitor)

(defindividual EvilCompetitor
  :type Competitor)

(refine scenario2/CompanyX
  :type Identity
  :fact
  (is knownByCompetitor EvilCompetitor))

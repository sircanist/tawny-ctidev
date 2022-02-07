(ns tawny-ctidev.cti2-scenario2-bk
  (:use [tawny.owl]
        [tawny-ctidev.cti2]
        [tawny-ctidev.cti2-scenario2])
  (:require [tawny-ctidev.utils :as utils])
  (:import
   (org.semanticweb.owlapi.apibinding OWLManager)
   (org.semanticweb.owlapi.profiles Profiles)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BACKGROUND KNOWLEDGE OF THE ATTACKER ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defontology cti2-scenario2-bk
  :iri "https://raw.githubusercontent.com/sircanist/ic-owl/dev/owls/cti2-scenario2-bk.owl"
  :prefix "cti2-sc2-bk:"
  :comment "Background knowledge of the possible attacker"
  :versioninfo "Unreleased Version"
  :seealso "Manchester Version")



(defoproperty has_alias)

(di CompanyX
    :type Organization
    :fact
    (is identity_name "CompanyX"))

(defclass BK1_WorksForCompanyXYZ
  :equivalent
  (has-value identity_name "BobMayer")
  :subclass
  (has-value works-for CompanyX))

(defclass BK2_IdentityCompanyAlias
  :equivalent
  (has-value identity_name "CompanyXYZ")
  :subclass
  (has-value has_alias CompanyX ))


(defclass BK2_IdentityCompanyAliasResolve
  :equivalent
  (has-value has_alias CompanyX)
  :subclass
  (oneof CompanyX))

(defclass BK_CompanyXVictim)

(defclass BK3_CompanyXVictim
  :equivalent
  (owl-and IncidentGrouping
           (owl-some grouping-ref (owl-some created-by (has-value works-for CompanyX))))
  :subclass
  BK_CompanyXVictim)

(defclass BK4_CompanyXVictim
  :equivalent
  (owl-and IncidentGrouping
           (owl-some grouping-ref (has-value created-by CompanyX)))
  :subclass
  BK_CompanyXVictim)


(defclass BK5_CompanyXVictim
  :equivalent
  (owl-and IncidentGrouping
           (owl-some grouping-ref (has-value targets CompanyX)))
  :subclass
  BK_CompanyXVictim)

(defclass BK6_CompanyXVictim
  :equivalent
  (owl-and IncidentGrouping
           (owl-some grouping-ref (owl-and Incident
                                           (has-value victim CompanyX))))
  :subclass
  BK_CompanyXVictim)


;; should not be necessary, as if not referenced by incident-grouping not shared anyways
;; (defclass CompanyIdentified3_sub
;;   :equivalent
;;   (has-value created-by CompanyX))

(defclass BK7_CompanyXVictim
  :equivalent
  (owl-and IncidentGrouping
           (owl-some grouping-ref (has-value works-for CompanyX)))
  :subclass BK_CompanyXVictim)

(defclass BK8_CompanyXVictim
  :equivalent
  (owl-and IncidentGrouping
           (has-value grouping-ref CompanyX))
  :subclass BK_CompanyXVictim)

(refine iIncidentGrouping
  :type IncidentGrouping)

(ns tawny-ctidev.core
  (:require [tawny-ctidev.utils :as utils]
            ;; [tawny-ctidev.cti :as cti]
            [tawny-ctidev.cti2 :as cti2]
            ;;[tawny-ctidev.scenario-1 :as scenario1]
            [tawny-ctidev.cti2-scenario1 :as cti2-scenario1]
            [tawny-ctidev.cti2-scenario1-bk :as cti2-scenario1-bk]
            [tawny-ctidev.cti2-scenario1-policy :as cti2-scenario1-policy]

            [tawny-ctidev.cti2-scenario2 :as cti2-scenario2]
            [tawny-ctidev.cti2-scenario2-bk :as cti2-scenario2-bk]
            [tawny-ctidev.cti2-scenario2-policy :as cti2-scenario2-policy]

            ;; [tawny-ctidev.scenario-1-attacker :as scenario1-attacker]
            ;; [tawny-ctidev.scenario-2-attacker :as scenario2-attacker]
            ;; [tawny-ctidev.scenario-2 :as scenario2]
            ))
;;[tawny-ctidev.scenario-1 :as scenario1])

;; removed old ontologies
;; (def cti {:path "cti.owl" :ontology cti/ctiontology})
;; (def scenario1 {:path "scenario1.owl" :ontology scenario1/cti-scenario1})
;; (def scenario2 {:path "scenario2.owl" :ontology scenario2/cti-scenario2})
;; (def scenario1-unwanted {:path "scenario1-unwanted.owl"})
;; (def scenario2-unwanted {:path "scenario2-unwanted.owl"})

;; (def scenario1-attacker {:path "scenario1-att.owl" :ontology scenario1-attacker/cti-attacker})
;; (def scenario2-attacker {:path "scenario2-att.owl" :ontology scenario2-attacker/cti-attacker})

(def cti2 {:path "output/cti2.owl" :ontology cti2/ctiontology2})
(def cti2-scenario1 {:path "output/cti2-scenario1.owl" :ontology cti2-scenario1/cti2-scenario1})
(def cti2-scenario1-bk {:path "output/cti2-scenario1-bk.owl" :ontology cti2-scenario1-bk/cti2-scenario1-bk})
(def cti2-scenario1-policy {:path "output/cti2-scenario1-policy.owl" :ontology cti2-scenario1-policy/cti2-scenario1-policy})

(def cti2-scenario2 {:path "output/cti2-scenario2.owl" :ontology cti2-scenario2/cti2-scenario2})
(def cti2-scenario2-bk {:path "output/cti2-scenario2-bk.owl" :ontology cti2-scenario2-bk/cti2-scenario2-bk})
(def cti2-scenario2-policy {:path "output/cti2-scenario2-policy.owl" :ontology cti2-scenario2-policy/cti2-scenario2-policy})

(defn save-ontology
  "save-ontology"
  [ontology-map]
  (utils/save-reload
   (ontology-map :path)
   (ontology-map :ontology)))

(defn verify-save-load-ontology
  "save-reload and additional verify owl profiles"
  [ontology-map]
  (utils/load-verified
   (ontology-map :path)
   (ontology-map :ontology)))

(defn verify-ontology
  "verifies the supplied ontology"
  [ontology-map]
  (utils/load-and-verify-ontology (:path ontology-map)))


(defn remove-annotations-and-tawny-import
  "call remove annotations to fix tawny export"
  [path]
  utils/remove-annotations path)

(defn -main [& args]
  (do
    ;; (save-ontology cti)
    ;; (save-ontology scenario1)
    ;; (save-ontology scenario1-attacker)
    ;; (save-ontology scenario2-attacker)
    ;; (save-ontology scenario2)
    (save-ontology cti2)
    (save-ontology cti2-scenario1)
    (save-ontology cti2-scenario1-bk)
    (save-ontology cti2-scenario1-policy)

    (save-ontology cti2-scenario2)
    (save-ontology cti2-scenario2-bk)
    (save-ontology cti2-scenario2-policy)

    ))


; what is secret in szenario1?
; and what does the attacker know:
; - ontology
; - additional info (add to static ontology):
;   -
;
;

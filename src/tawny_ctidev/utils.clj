(ns tawny-ctidev.utils
  (:require [clojure.tools.logging :as log]
            [clojure.string :as string]
            [clojure.java.io :as io]
            [clojure.xml :as xml]
            [clojure.zip :as zip]
            [clojure.data.zip.xml :refer [xml-> xml1-> attr text]]
            [clojure.java.shell :as sh])
  (:use [tawny owl pattern])
  (:import
    (org.semanticweb.owlapi.apibinding OWLManager)
    (org.semanticweb.owlapi.profiles Profiles)))


(defn load-ontology
  "Given a path to an ontology file load and return the ontology."
  ([ontology-path]
   (log/info "Loading ontology:" ontology-path)
   (let [manager (OWLManager/createOWLOntologyManager)]
     (let [ontology (.loadOntologyFromOntologyDocument
                      manager
                      (io/file ontology-path))]
       ontology))))

(defn get-report [ontology profile] (.checkOntology profile ontology))

(defn pp-report
  "create the ontology profile report for an ontology"
  [ontology profile]
  (let [report (get-report ontology profile)]
    (println (str report))))


(defn remove-ontology
  "removes the ontology from disk"
  [ontology-path]
  (sh/sh "rm" (str ontology-path)))

(defn print-allreports
  "print the reports for checking of owl profiles"
  [ontology]
    (pp-report ontology Profiles/OWL2_FULL)
    (pp-report ontology Profiles/OWL2_DL)
    (pp-report ontology Profiles/OWL2_RL)
    (pp-report ontology Profiles/OWL2_EL))

(defn load-and-verify-ontology
  "loads and verifies the ontology from the supplied path"
  [ontology-path]
  (let [ontology (load-ontology ontology-path)]
    (println (str ontology-path))
    (println (str ontology))
    (print-allreports ontology)
    ontology))

(defn remove-annotations
  "removes the annotations, tawny creates, as they are incorrect"
  [path]
  (do
    (sh/sh "sed" "-i" "/<AnnotationAssertion>/,/<\\/AnnotationAssertion>/d"
          (str path))
    (sh/sh "sed" "-i" "/<Annotation>/,/<\\/Annotation>/d"
          (str path))
    (sh/sh "sed" "-i" "/<Import>http\\:\\/\\/www.purl.org\\/ontolink/d"
           (str path))))



(defn save-reload
  "executes a save reload dance until ontology is correctly saved"
  [path ontology]
  (remove-ontology path)
  (save-ontology ontology path :owl)
  (load-ontology path)
  (save-ontology ontology path :owl)
  (remove-annotations path)
  )

(defn load-verified
  "save, load and then verify ontology ()"
  ([path ontology]
   (save-reload path ontology)
   (load-and-verify-ontology path)))

(defn get-classes
  "helper to get all classes from an ontology"
  [ontology]
  (.getClassesInSignature ontology))

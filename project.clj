(defproject tawny_ctidev "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :main "tawny-ctidev.core"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.2"]
                 [uk.org.russet/tawny-owl "2.0.3"]
                 [org.clojure/tools.trace "0.7.11"]
                 [net.sourceforge.owlapi/owlapi-distribution "4.5.16"]
                 [org.clojure/tools.logging "0.2.6"]
                 [org.codehaus.woodstox/woodstox-core-asl "4.3.0"]
                 [org.clojure/data.zip "0.1.2"]]
  :repl-options {:init-ns tawny-ctidev.core}
  :user {:dependencies [[clj-kondo "RELEASE"]]
         :aliases {"clj-kondo" ["run" "-m" "clj-kondo.main"]}})

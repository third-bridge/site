;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.alpha.application
  (:require
   [juxt.pass.alpha :as-alias pass]
   [juxt.site.alpha :as-alias site]
   [juxt.site.alpha.util :refer [as-hex-str random-bytes]]))

(defn make-application-doc [& {:keys [prefix client-id client-secret]}]
  {:xt/id (str prefix client-id)
   ::site/type "Application"
   ::pass/oauth2-client-id client-id
   ::pass/oauth2-client-secret client-secret})

(defn make-application-authorization-doc [& {:keys [prefix user application]}]
  {:xt/id (str prefix (as-hex-str (random-bytes 10)))
   ::site/type "ApplicationAuthorization"
   ::pass/user user
   ::pass/application application})

(defn make-access-token-doc [& {:keys [prefix user application scope]}]
  (let [token (as-hex-str (random-bytes 16))]
    {:xt/id (str prefix token)
     ::site/type "AccessToken"
     ::pass/user user
     ::pass/application application
     ::pass/scope scope
     ::pass/token token}))

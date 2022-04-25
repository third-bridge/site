;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.alpha.application
  (:require
   [juxt.pass.alpha :as-alias pass]
   [juxt.site.alpha :as-alias site]))

(defn make-application-doc [& {:keys [prefix client-id client-secret]}]
  {:xt/id (str prefix client-id)
   ::site/type "Application"
   ::pass/oauth2-client-id client-id
   ::pass/oauth2-client-secret client-secret})

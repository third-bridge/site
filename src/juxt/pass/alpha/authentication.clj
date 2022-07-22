;; Copyright © 2021, JUXT LTD.

(ns juxt.pass.alpha.authentication
  (:require
   [clojure.tools.logging :as log]
   [juxt.reap.alpha.decoders :as reap]
   [juxt.reap.alpha.rfc7235 :as rfc7235]

   [juxt.pass.alpha :as-alias pass]
   [juxt.site.alpha :as-alias site])
  (:import
   (com.auth0.jwt JWT)))

(defn authenticate
  "Authenticate a request. Return a pass subject, with information about user,
  roles and other credentials. The resource can be used to determine the
  particular Protection Space that it is part of, and the appropriate
  authentication scheme(s) for accessing the resource."
  [req]
  (when-let [authorization-header (get-in req [:ring.request/headers "authorization"])]
    (let [{::rfc7235/keys [auth-scheme token68]}
          (reap/authorization authorization-header)]
      (case (.toLowerCase auth-scheme)
        "bearer"
        (when-let [jwt (bean (JWT/decode token68))]
          (log/debug "Valid JWT found" jwt)
          (->
           jwt
           (assoc ::pass/auth-scheme "Bearer"
                  ::pass/subject (:subject jwt)
                  ::pass/session-expiry (:expiresAt jwt))))

        (throw
         (ex-info
          "Auth scheme unsupported, must be a bearer token"
          {::site/request-context (assoc req :ring.response/status 401)}))))))

;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.alpha.authorization-2
  (:require
   [juxt.site.alpha.util :refer [sha random-bytes as-hex-str as-b64-str uuid-bytes]]
   [xtdb.api :as xt]
   [clojure.set :as set]
   [clojure.tools.logging :as log]))

(alias 'http (create-ns 'juxt.http.alpha))
(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(defn id-token->subject [id-token db]
  (let [iss (get-in id-token [:claims "iss"])
        sub (get-in id-token [:claims "sub"])]
    (ffirst
     (xt/q db '{:find [(pull subject [*])]
                :where [[identity ::pass/subject subject]
                        [identity :juxt.pass.jwt/iss iss]
                        [identity :juxt.pass.jwt/sub sub]]
                :in [iss sub]}
           iss sub))))

(defn make-application
  ;; Create a new application, return the app-details with :xt/id
  [{::site/keys [base-uri]}]
  (let [client-id (subs (as-hex-str (sha (uuid-bytes))) 0 10)
        client-secret (as-b64-str (random-bytes 24))]
    {:xt/id (str base-uri "/_site/apps/" client-id)
     ::pass/client-id client-id
     ::pass/client-secret client-secret}))

(comment
  (make-application {::site/base-uri "https://example.org"}))

(defn token-id->xt-id [token-id]
  (format "urn:site:access-token:%s" token-id))

(defn make-access-token
  "Returns a map representing an access token. Can be augmented
  with :juxt.pass.alpha/scope and other entries."
  ([subject-id client-id]
   (let [token-id (as-hex-str (random-bytes 20))]
     {:xt/id (token-id->xt-id token-id)
      ::pass/subject subject-id
      ;; TODO: We may harmonize these keywords with openid_connect if we decide
      ;; OAuth2 is the standard default.
      ::pass/client client-id}))
  ([subject-id client-id scope]
   (-> (make-access-token subject-id client-id)
       (assoc ::pass/scope scope))))


(defn rules
  "Construct rules from a ruleset id"
  [db ruleset]
  (assert ruleset)
  (assert (string? ruleset))
  (->>
   (xt/q
    db
    '{:find [rule-content]
      :where [[ruleset ::pass/rules rule]
              [rule ::pass/rule-content rule-content]]
      :in [ruleset]}
    ruleset)
   (map (comp read-string first))
   (mapcat seq)
   vec))

(defn access-token-effective-scope
  "Return a set representing the scope of the access-token. The scope of an
  access-token defaults to the scope of application client it applies
  to. However, access-tokens may be issued with more restrictive scope."
  [access-token client]
  (assert (map? access-token))
  (assert (map? client))
  (if-let [access-token-scope (::pass/scope access-token)]
    (set/intersection access-token-scope (::pass/scope client))
    (::pass/scope client)))

(defn check
  [db {::site/keys [uri]
       ::pass/keys [access-token-effective-scope subject ruleset]}
   required-scope]

  (assert db)
  (assert access-token-effective-scope)
  (assert (set? access-token-effective-scope))
  (assert subject)
  (assert ruleset)
  (assert (string? ruleset))
  (assert required-scope)
  (assert (set? required-scope))
  ;; Due to the way that XT treats sets as many-cardinality references, we avoid
  ;; this issue by restricting required-scopes to single privilege. TODO: Is
  ;; 'privilege' the right word here?
  (assert (= (count required-scope) 1) "A required-scope can currently contain one privilege")

  ;; uri can be nil

  ;; First, an easy check to see if the action is allowed with respect to the
  ;; scope on the application client and, if applicable, any scope on the
  ;; access-token itself.
  (when-not (set/superset? access-token-effective-scope required-scope)
    (throw
     (ex-info
      (format "Scope of access-token does not allow %s" required-scope)
      {:required-scope required-scope
       :access-token-effective-scope access-token-effective-scope})))

  ;; TODO:

  (let [rules (rules db ruleset)

        _ (log/tracef "Rules are %s" rules)

        query {:find ['(pull acl [*])]
               :where '[
                        ;; Site enforced
                        [acl ::site/type "ACL"]
                        [acl ::pass/scope action]
                        ;; Custom
                        (acl-applies-to-subject? acl subject)
                        (acl-applies-to-resource? acl resource)]
               :rules rules
               :in '[access-token action resource]}]
    (when (seq rules)
      (seq (map first (xt/q db query subject (first required-scope) uri))))))


(defn check-fn [db auth required-scope]
  (try
    (let [acls (check db auth required-scope)]
      (log/tracef "acls are %s" acls)
      acls
      )
    (catch Throwable e
      (log/error e "Failed authorization check")
      (throw e))))

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

(defn lookup->subject [id-token db]
  (let [iss (get-in id-token [:claims "iss"])
        sub (get-in id-token [:claims "sub"])]
    (ffirst
     (xt/q db '{:find [(pull subject [*])]
                :where [[identity ::pass/subject subject]
                        [identity :juxt.pass.jwt/iss iss]
                        [identity :juxt.pass.jwt/sub sub]]
                :in [iss sub]}
           iss sub))))

(defn make-oauth-client-doc
  "Return an XT doc representing an OAuth2 client (with a random client-id if not
  given) and random client-secret. This must be added to the database."
  ([{::site/keys [base-uri]} client-id]
   (let [client-secret (as-b64-str (random-bytes 24))]
     {:xt/id (str base-uri "/_site/apps/" client-id)
      ::pass/client-id client-id
      ::pass/client-secret client-secret}))
  ([ctx]
   (make-oauth-client-doc ctx (subs (as-hex-str (sha (uuid-bytes))) 0 10))))

(comment
  (make-oauth-client-doc {::site/base-uri "https://example.org"}))

(defn token-id->xt-id [token-id]
  (format "urn:site:access-token:%s" token-id))

(defn make-access-token-doc
  "Returns an XT doc representing an access token. Can be augmented
  with :juxt.pass.alpha/scope and other entries."
  ([subject-id client-id]
   (let [token-id (as-hex-str (random-bytes 20))]
     {:xt/id (token-id->xt-id token-id)
      ::pass/subject subject-id
      ;; TODO: We may harmonize these keywords with openid_connect if we decide
      ;; OAuth2 is the standard default.
      ::pass/client client-id}))
  ([subject-id client-id scope]
   (-> (make-access-token-doc subject-id client-id)
       (assoc ::pass/scope scope))))

(defn rules
  "Construct rules from a ruleset id"
  [db ruleset]
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

#_(defn check-scope [access-token-effective-scope action]
  (assert (set? access-token-effective-scope))
  (assert (string? action))
  ;; First, an easy check to see if the action is allowed with respect to the
  ;; scope on the application client and, if applicable, any scope on the
  ;; access-token itself.
  (when-not (contains? access-token-effective-scope action)
    (throw
     (ex-info
      (format "Scope of access-token does not allow %s" action)
      {:action action
       :access-token-effective-scope access-token-effective-scope}))))

(defn check-acls
  [db {::site/keys [uri]
       ::pass/keys [subject ruleset access-token-effective-scope]}
   command]

  (assert db)
  (assert subject)
  (assert (string? ruleset))
  (assert (string? command))

  (let [rules (rules db ruleset)]

    (when (seq rules)
      (let [query
            {:find ['(pull acl [*])]
             :where '[
                      ;; Site enforced
                      [acl ::site/type "ACL"]
                      [acl ::pass/command command]

                      [command ::site/type "Command"]

                      ;; Scope
                      [command ::pass/scope scope]
                      [(contains? access-token-effective-scope scope)]

                      ;; Custom
                      (acl-applies-to-subject? acl subject)
                      (acl-applies-to-resource? acl resource)]
             :rules rules
             :in '[access-token action resource access-token-effective-scope]}]
        (seq (map first (xt/q db query subject command uri access-token-effective-scope)))))))

(defn check [db auth action]
  #_(check-scope (::pass/access-token-effective-scope auth) action)
  (check-acls db auth action))

(defn authorizing-put-fn [db {::pass/keys [ruleset] :as auth} command doc]
  (assert ruleset)

  (try
    (let [acls (check-acls db auth command)]

      (log/tracef "ACLs are %s" acls)

      (when (nil? acls)
        (let [msg "Transaction function call denied as no ACLs found that approve it."]
          (log/warnf msg)
          (throw (ex-info msg {}))))

      (when-not (.startsWith (:xt/id doc) (::site/uri auth))
        (let [msg ":xt/id of new document must be a sub-resource of ::site/uri"]
          (log/warnf msg)
          (throw (ex-info msg {:new-doc-id (:xt/id doc)
                               ::site/uri auth}))))

      (if acls
        [[::xt/put
          ;; Critically, the new doc inherits the ruleset of the auth
          ;; context. This prevents documents from escaping their authorization
          ;; scheme into another.
          (let [doc (assoc doc ::pass/ruleset ruleset)]
            doc)]]
        []))

    (catch Throwable e
      (log/error e "Failed authorization check")
      (throw e))))

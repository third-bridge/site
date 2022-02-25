;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.acl-test-2
  (:require
   [clojure.test :refer [deftest is are testing] :as t]
   [juxt.pass.alpha.authorization-2 :as authz]
   [juxt.test.util :refer [with-xt with-handler submit-and-await!
                           *xt-node* *handler*]]
   [xtdb.api :as xt]))

(alias 'apex (create-ns 'juxt.apex.alpha))
(alias 'http (create-ns 'juxt.http.alpha))
(alias 'pick (create-ns 'juxt.pick.alpha))
(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(t/use-fixtures :each with-xt with-handler)

(defn fail [ex-data] (throw (ex-info "FAIL" ex-data)))

(defn expect
  ([result pred ex-info]
   (is (pred result))
   (let [pred-result (pred result)]
     (when-not pred-result
       (fail (into ex-info {:pred pred :result result :pred-result pred-result}))))
   result)
  ([result pred]
   (expect result pred {})))

(defn with-scenario [f]
  (submit-and-await!
   [
    [::xt/put
     {:xt/id "https://example.org/people/sue"
      ::pass/ruleset "https://example.org/ruleset"}]

    ;; A person may have many identities
    [::xt/put
     {:xt/id "https://example.org/people/sue/identities/example"
      ::site/type "Identity"
      :juxt.pass.jwt/iss "https://example.org"
      :juxt.pass.jwt/sub "sue"
      ::pass/subject "https://example.org/people/sue"
      ::pass/ruleset "https://example.org/ruleset"}]

    [::xt/put
     {:xt/id "https://example.org/people"
      ::pass/ruleset "https://example.org/ruleset"}]

    [::xt/put
     {:xt/id "https://example.org/commands/create-user"
      ::site/type "Command"
      ::pass/scope "admin:write"}]

    [::xt/put
     {:xt/id "https://example.org/acls/sue-can-create-users"
      ::site/type "ACL"
      ::pass/subject "https://example.org/people/sue"
      ::pass/command "https://example.org/commands/create-user"
      ::pass/resource "https://example.org/people/"}]

    [::xt/put
     {:xt/id "https://example.org/rules/1"
      ::site/description "Allow read access of resources to granted subjects"
      ::pass/rule-content
      (pr-str '[[(acl-applies-to-subject? acl subject)
                 [acl ::pass/subject subject]]
                [(acl-applies-to-resource? acl resource)
                 [acl ::pass/resource resource]]])}]

    ;; We can now define the ruleset
    [::xt/put
     {:xt/id "https://example.org/ruleset"
      ::pass/rules ["https://example.org/rules/1"]}]

    [::xt/put
     {:xt/id ::pass/authorizing-put
      :xt/fn '(fn [ctx auth command doc]
                (let [db (xtdb.api/db ctx)]
                  (juxt.pass.alpha.authorization-2/authorizing-put-fn db auth command doc)))}]

    [::xt/put
     (into
      {::pass/name "Site Admininistration"
       ;; If specified (and it must be currently), ::pass/scope overrides
       ;; the subject's default scope.
       ::pass/scope
       #{"admin:write"}}
      (authz/make-oauth-client-doc {::site/base-uri "https://example.org"} "admin-client"))]

    [::xt/put
     (into
      {::pass/name "Example App"
       ;; If specified (and it must be currently), ::pass/scope overrides
       ;; the subject's default scope.
       ::pass/scope
       #{"read:index"
         "read:document" "write:document"
         "read:directory-contents" "write:create-new-document"}}
      (authz/make-oauth-client-doc {::site/base-uri "https://example.org"} "example-client"))]

    #_guest-client
    #_(into
       {::pass/name "Guest Access"
        ::pass/scope #{"read:index" "read:document"}}
       (authz/make-oauth-client-doc
        {::site/base-uri "https://example.org"}))

    #_#__ (submit-and-await!
           [
            [::xt/put guest-client]])
    ])
  (f))

(defn acquire-access-token [sub client-id db]
  (let [
        ;; First we'll need the subject. As a performance optimisation, we can
        ;; associate the subject with the stored access token itself, rather
        ;; than re-establish the subject on each request via the id-token
        ;; claims, because we assume the claims can never apply to a different
        ;; subject. However, this assertion needs to be written up and
        ;; communicated. If claims were ever to be reassigned to a different
        ;; subject, then all access-tokens would need to be made void
        ;; (removed).
        subject
        (authz/lookup->subject {:claims {"iss" "https://example.org" "sub" sub}} db)

        ;; The access-token links to the application, the subject and its own
        ;; scopes. The overall scope of the request is ascertained at each and
        ;; every request.
        access-token
        (into
         (authz/make-access-token-doc
          (:xt/id subject)
          client-id
          ;;#{"read:document"}
          ))]

    ;; An access token must exist in the database, linking to the application,
    ;; the subject and its own granted scopes. The actual scopes are the
    ;; intersection of all three.
    (submit-and-await! [[::xt/put access-token]])

    (:xt/id access-token)))

(defn authorize-request [{::site/keys [db] :as req} access-token-id]
  (let [access-token (xt/entity db access-token-id)

        ;; Establish subject and client
        {:keys [subject client]}
        (first
         (xt/q
          db
          '{:find [subject
                   (pull client [:xt/id ::pass/client-id ::pass/scope])]
            :keys [subject client]
            :where [[access-token ::pass/subject subject]
                    [access-token ::pass/client client]]
            :in [access-token]}
          access-token-id))]

    ;; Bind onto the request. For performance reasons, the actual scope
    ;; is determined now, since the db is now a value.
    (assoc req
           ::pass/subject subject
           ::pass/client client
           ::pass/access-token-effective-scope
           (authz/access-token-effective-scope access-token client)
           ::pass/access-token access-token
           ::pass/ruleset "https://example.org/ruleset"
           )))

(defn new-request [uri db access-token-id opts]
  (assert access-token-id)
  (let [req (merge {::site/db db ::site/uri uri} opts)]
    (authorize-request req access-token-id)))

(defn authorizing-put! [{::pass/keys [access-token-effective-scope] :as req}
                        & action-docs]

  (let [
        ;; We construct an authentication/authorization 'context', which we
        ;; pass to the function and name it simply 'auth'. Entries of this
        ;; auth context will be used when determining whether access is
        ;; approved or denied.
        auth (-> req
                 (select-keys
                  [::pass/subject
                   ::pass/client
                   ::pass/access-token-effective-scope
                   ::pass/ruleset
                   ;; The URI may be used as part of the context, e.g. PUT to
                   ;; /documents/abc may be allowed but PUT to /index may not
                   ;; be.
                   ::site/uri]))

        tx (xt/submit-tx
            *xt-node*
            (mapv
             (fn [[action doc]]
               [:xtdb.api/fn ::pass/authorizing-put auth action doc])
             action-docs))
        tx (xt/await-tx *xt-node* tx)]

    ;; Currently due to https://github.com/xtdb/xtdb/issues/1672 the only way of
    ;; checking whether this tx was authorized is by checking it committed. We
    ;; don't get any errors through, so all we can do is point at the logs.
    (when-not (xt/tx-committed? *xt-node* tx)
      (throw
       (ex-info
        "Failed to commit, check logs"
        {:auth auth
         :action-docs action-docs
         })))))

;; As above but building up from a smaller seed.
((t/join-fixtures [with-xt with-handler with-scenario])
 (fn []

   (let [db (xt/db *xt-node*)
         ;; Access tokens for each sub/client pairing
         access-tokens
         {["sue" "admin-client"] (acquire-access-token
                                  "sue" "https://example.org/_site/apps/admin-client"
                                  db)
          ["sue" "example-client"] (acquire-access-token
                                  "sue" "https://example.org/_site/apps/example-client"
                                  db)}]

     ;; Sue creates a new user, Alice
     (let [db (xt/db *xt-node*)

           ;; Check ACLs on correct request
           #_#__ (->
                  (authz/check-acls
                   db
                   (new-request
                    "https://example.org/people/"
                    db
                    (get access-tokens ["sue" "admin-client"])
                    {:request-body-doc {:xt/id "https://example.org/people/alice"}})
                   "https://example.org/commands/create-user")
                  (expect (comp not zero? count)))

           ;; TODO: Wrong person
           ;; TODO: Wrong app
           ;; TODO: Wrong command

           #_#_req (new-request
                    "https://example.org/people/"
                    db
                    (get access-tokens ["sue" "admin-client"])
                    {:request-body-doc {:xt/id "https://example.org/people/alice"}})]



       ;; TODO: Create a language of commands.

       ;; Each command is associated, many-to-one, with a required (single)
       ;; scope. If an OpenAPI document defines an operation, that operation may
       ;; involve multiple commands, and the security requirement might require
       ;; multiple scopes. The security requirement of scopes may be implied
       ;; (and may affect the publishing of the openapi.json such that authors
       ;; don't need to concern themselves with declaring scope).

       ;; A command such as 'create-user' is registered in the database.

       ;; Scopes are an access token concern. An access token references an
       ;; application which references a particular API. Commands are therefore
       ;; part of the domain to which an API belongs. A GraphQL endpoint is
       ;; defined as part of an overall OpenAPI, which is the same group where
       ;; scopes, commands and rulesets are defined.

       ;; create-user is in the 'admin:write' scope.

       ;; create-user is defined with a description that can be showed to users
       ;; for the purposes of informed authorization.

       ;; The 'create-user' command determines the applicable ACLs.

       ;; Subjects are mapped to commands. Applications are mapped to scopes.

       ;; Now to call 'create-user'
       (let [req (new-request
                  "https://example.org/people/"
                  db
                  (get access-tokens ["sue" "admin-client"])
                  {:request-body-doc {:xt/id "https://example.org/people/alice"}})]
         (authorizing-put!
          req
          ;; The request body would be transformed into this new doc
          ["https://example.org/commands/create-user" (:request-body-doc req)]

          ;; TODO: We need to create some ACLs for this user, ideally in the same tx
          ))

       )

     #_(let [db (xt/db *xt-node*)]
         (expect
          (xt/entity db "https://example.org/people/alice")
          #(= (::pass/ruleset %) "https://example.org/ruleset"))

         :ok
         (xt/entity db "https://example.org/people/alice")


         ))

   ;; If accessing the API directly with a browser, the access-token is
   ;; generated and stored in the session (accessed via the cookie rather than
   ;; the Authorization header).

   ;; The bin/site tool might have to be configured with the client-id of the
   ;; 'Admin App'.

   ;; TODO: Sue creates Alice, with Alice's rights
   ;; scope is 'create:user'

   ;; Could we have an underlying 'DSL' that can be used by both OpenAPI and
   ;; GraphQL? Rather than OpenAPI wrapping GraphQL (and therefore requiring
   ;; it), could we have both call an underlying 'Site DSL' which integrates
   ;; scope-based authorization?

   ;; Consider a 'create-user' command. Might these be the events that jms
   ;; likes to talk about? A command is akin to set of GraphQL mutations,
   ;; often one per request.

   ;; Commands can cause mutations and also side-effects.

   ;; Consider a command: create-user - a command can be protected by a scope,
   ;; e.g. write:admin

   ;; Commands must just be EDN.

   ))


;; When mutating, use info in the ACL(s) to determine whether the document to
;; 'put' meets the defined criteria. This can restrict the URI path to enforce a
;; particular URI organisation. For example, a person writing an object might be
;; restricted to write under their own area.

;; Allowed methods reported in the Allow response header may be the intersection
;; of methods defined on the resource and the methods allowed by the 'auth'
;; context.

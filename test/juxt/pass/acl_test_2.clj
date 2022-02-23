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
   (when-not (pred result)
     (fail (into ex-info {:pred pred :result result})))
   result)
  ([result pred]
   (expect result pred {})))

;; As above but building up from a smaller seed.
((t/join-fixtures [with-xt with-handler])
 (fn []
   (submit-and-await!
    [
     [::xt/put
      {:xt/id "https://example.org/people/sue"
       ::pass/ruleset "https://example.org/ruleset"}]

     ;; An person may have many identities
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
      {:xt/id "https://example.org/acls/sue-can-create-users"
       ::site/type "ACL"
       ::pass/subject "https://example.org/people/sue"
       ::pass/scope #{"create:user"}
       ::pass/resource "https://example.org/people/"
       }]

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

     ;; TODO: Need a ruleset to allow Sue to create Alice

     [::xt/put
      {:xt/id ::pass/secure-put
       :xt/fn '(fn [ctx auth required-scope doc]
                 (let [db (xtdb.api/db ctx)]
                   (if (juxt.pass.alpha.authorization-2/check-fn db auth required-scope)
                       ;; TODO: Now to check the doc with respect to the acls found
                     [[::xt/put doc]]
                     []
                     #_(throw (ex-info "Fail!" {})))))}]])

   (let [admin-client
         (into
          {::pass/name "Site Admininistration"
           ;; If specified (and it must be currently), ::pass/scope overrides
           ;; the subject's default scope.
           ::pass/scope
           #{"read:index"
             "read:document" "write:document"
             "read:directory-contents" "write:create-new-document"
             "create:user"}}
          (authz/make-application {::site/base-uri "https://example.org"}))

         guest-client
         (into
          {::pass/name "Guest Access"
           ::pass/scope #{"read:index" "read:document"}}
          (authz/make-application
           {::site/base-uri "https://example.org"}))

         _ (submit-and-await!
            [
             [::xt/put admin-client]
             [::xt/put guest-client]])

         db (xt/db *xt-node*)

         ;; Having chosen the client application, we acquire a new access-token.

         ;; First we'll need the subject. We can put the subject into the access
         ;; token rather than the claims, because we assume the claims can never
         ;; apply to a different subject. However, this assertion needs to be
         ;; written up and communicated. If claims were ever to be reassigned to
         ;; a different subject, then all access-tokens would need to be made
         ;; void (removed).
         subject (-> {:claims {"iss" "https://example.org" "sub" "sue"}}
                     (authz/id-token->subject db))

         access-token
         (into
          (authz/make-access-token
           (:xt/id subject)
           (:xt/id admin-client)
           ;;#{"read:document"}
           ))

         ;; An access token must exist in the database, linking to the application,
         ;; the subject and its own granted scopes. The actual scopes are the
         ;; intersection of all three.

         _ (submit-and-await!
            [[::xt/put access-token]])
         ]

     ;; The access-token links to the application, the subject and its own
     ;; scopes. The overall scope of the request is ascertained at each and
     ;; every request.
     access-token

     ;; A new request arrives
     (let [db (xt/db *xt-node*)

           req {}

           ;; Establish the access-token (TODO), either via bearer token or
           ;; cookie session
           access-token-id (:xt/id access-token)

           ;; Establish subject and client
           {:keys [subject client]}
           (first
            (xt/q
             db
             '{:find [(pull subject [*])
                      (pull client [:xt/id ::pass/client-id ::pass/scope])]
               :keys [subject client]
               :where [[access-token ::pass/subject subject]
                       [access-token ::pass/client client]]
               :in [access-token]}
             access-token-id))

           ;; Bind onto the request
           req
           (assoc req
                  ::pass/subject subject
                  ::pass/client client
                  ::pass/access-token-effective-scope (authz/access-token-effective-scope access-token client)
                  ::pass/access-token access-token
                  ::pass/ruleset "https://example.org/ruleset"
                  ::site/uri "https://example.org/people/")]

       (->
        (authz/check db (assoc req ::site/uri "https://example.org/") #{"create:user"})
        (expect (comp zero? count)))

       ;; create:user is a 'global' privilege, where the ACLs are restricted to
       ;; a given URI.
       (->
        (authz/check db req #{"create:user"})
        (expect (comp not zero? count)))

       ;; Now to call create-user!
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

             new-user-doc
             {:xt/id "https://example.org/people/alice"
              ::pass/ruleset "https://example.org/ruleset"}

             tx (xt/submit-tx
                 *xt-node*
                 [[:xtdb.api/fn ::pass/secure-put auth #{"create:user"} new-user-doc]])
             tx (xt/await-tx *xt-node* tx)]

         (xt/tx-committed? *xt-node* tx)
         )

       )

     ;; Perf: The actual scope should be determined at request time and bound to
     ;; the request.

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

     )))


;; When mutating, use info in the ACL(s) to determine whether the document to
;; 'put' meets the defined criteria. This can restrict the URI path to enforce a
;; particular URI organisation. For example, a person writing an object might be
;; restricted to write under their own area.

;; Allowed methods reported in the Allow response header may be the intersection
;; of methods defined on the resource and the methods allowed by the 'auth'
;; context.

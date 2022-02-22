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
       ::pass/scope "create:user"
       ::pass/resource "https://example.org/people"
       }]

     [::xt/put
      {:xt/id "https://example.org/rules/1"
       ::site/description "Allow read access of resources to granted subjects"
       ::pass/rule-content
       (pr-str '[[(check acl subject action resource)
                  [acl ::site/type "ACL"]
                  [acl ::pass/resource resource]

                  ;; Ensure client application has scope
                  #_[access-token ::pass/client client]
                  #_[client ::pass/scope action]

                  ;; Join on action
                  #_[access-token ::pass/scope action]
                  #_[acl ::pass/scope action]

                  #_[acl ::pass/resource resource]

                  #_[access-token ::pass/scope action]]

                 ])}]

     ;; We can now define the ruleset
     [::xt/put
      {:xt/id "https://example.org/ruleset"
       ::pass/rules ["https://example.org/rules/1"]}]

     ;; TODO: Need a ruleset to allow Sue to create Alice
     ])

   #_[::xt/put {:xt/id :create-user!
                :xt/fn '(fn [ctx eid]
                          (let [db (xtdb.api/db ctx)
                                entity (xtdb.api/entity db eid)]
                            [[::xt/put (update entity :age inc)]]))}]

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

         ;;claims

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

           req {::site/db db}

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
                  ::pass/access-token access-token)]

       req

       (authz/check
        req "create:user" "https://example.org/people")

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
